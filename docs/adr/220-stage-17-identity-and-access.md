# ADR-220 — S17: enterprise identity & access

> **Owner:** ARACHNE architecture group · **Last verified:** 2026-11-05 · **Review interval:** 1825 days

Status: accepted (S17, program Phase 2)

This stage puts corporate identity in front of the platform without weakening the
posture that made it adoptable: SSO becomes another way in, never the only one, and a
deployment with nothing configured is exactly as closed as it was before. It implements
capability area `IDAM` (REQ-IDAM-001...005) under the standing rules — deny by default,
hashing discipline unchanged, every refusal audited, no default server dependency added.

---

## 220.1 — OIDC alongside API keys, not instead of them

The authentication path is one `CredentialStore` over three credential types:

1. **static keys** (`ARACHNE_API_KEYS`, the S12 mechanism, unchanged);
2. **service accounts** (DB-backed, §220.4);
3. **SSO sessions** (OIDC, this section).

`authenticate` tries the presented key (header `X-API-Key` or the UI cookie), then the
SSO session cookie; the first that resolves wins. `CredentialStore.enabled` is true only
if *something* can authenticate, so a deployment with no keys, no accounts and no IdP
refuses every request (`401`) — REQ-IDAM-002's deny-by-default half, asserted by a test
that also proves the SSO routes return `503` when unconfigured.

The login is the standard authorization-code flow with PKCE `S256` and an OIDC `nonce`:
`GET /api/v1/auth/sso/login` mints `state` + `nonce` + verifier, persists the pending flow
server-side and 302s to the IdP; `GET /api/v1/auth/sso/callback` consumes the flow (the
`state` is its primary key and single-use), exchanges the code, verifies the ID token
against the provider JWKS, maps groups to a role, and mints an opaque session cookie.

**Why server-side flow state and not a signed cookie.** The PKCE verifier and nonce must
not ride in the browser, and a callback can land on any node of a distributed deployment
(§S16). The store is the truth, as everywhere else; `sso_flows` rows expire on their own
TTL and are deleted on first use.

## 220.2 — The verifier is small, explicit, and stdlib-only

`api/oidc.py` implements JWT verification without a crypto dependency: HS256/384/512 via
`hmac`, RS256/384/512 via RSASSA-PKCS1-v1_5 (`pow(signature, e, n)` plus the DigestInfo
padding check). Checks, in order: structure, `alg` against a configured allowlist (never
`none`, never a family/algorithm mismatch — an HS256 token cannot ride an RS256-only
allowlist), key selection by `kid` (a multi-key JWKS refuses an unmatched `kid` rather
than guessing), signature, `iss`, `aud`, `exp`/`nbf` with leeway, and the `nonce`. There
is no code path that returns unverified claims. The verifier is exercised against a fixed
RSA keypair, an RFC 7636 PKCE vector, and the negative cases (tampered payload, garbage
signature, wrong issuer/audience/nonce, expired token, alg confusion).

The default install stays dependency-light (C-01): no `cryptography`, no `pyjwt`, no
`authlib` enters `pyproject.toml`.

## 220.3 — One redaction exemption, and it is not the scanning client

The token exchange must read credentials *back* to function; a redacted ID token is not a
token. `ScopedHttpClient` gained an explicit instance flag (`redaction_enabled`) whose
**only** caller is the OIDC provider's dedicated client. That client:

* pins its scope to the IdP host(s), so egress is as bounded as a scan's (ADR-05);
* never logs or persists the exchange — the `http.request` audit line carries only the
  response's SHA-256, and the module never echoes a token body (not even on error);
* is constructed per application context and closed on shutdown.

The scanning client is untouched and still redacts at capture. The exemption is asserted
by the fact that no other call site passes the flag; the security review records it.

## 220.4 — API keys become service accounts

`service_accounts` (migration `0006`) holds the same SHA-256 digest format the S12 key
store uses — the storage-format test is unchanged — plus the three things REQ-IDAM-003
adds:

* **optional expiry** (`expires_at`, `NULL` = does not expire);
* **last-used tracking** (`last_used_at`, stamped on each successful verify);
* **rotation** (`POST /api/v1/service-accounts/{label}/rotate`): the digest is replaced
  in place, so the old secret stops working immediately and the new one is returned
  exactly once; `rotated_from` plus a rotation counter in `meta_json` keep the lineage,
  and a *revoked* account is retained (never hard-deleted) so "this key existed and was
  turned off" is answerable. Revocation is explicit
  (`POST .../revoke`).

Verification stays `hmac.compare_digest` over all rows; a revoked/expired row is refused
*after* the digest matches, so timing does not reveal whether the secret was right.

## 220.5 — Actor identity: "user X via key Y"

`Principal` now carries both halves — `user` (the human: an SSO email/name, or a service
account's `owner`) and `credential` (the key label presented). Its `actor` property
composes REQ-IDAM-004's form:

| Situation | `actor` |
|---|---|
| SSO session | `user alice@corp` |
| service account with an owner | `user alice@corp via key ci-pipeline` |
| static key / ownerless account | `key ci-pipeline` |
| no credential | `anonymous` |

The audit middleware signs `api.request` with that identity (and keeps the bare key
label in `meta["actor"]` for compatibility, with the composed form in `meta["identity"]`);
user-initiated route actions use `auditor.with_actor(principal.actor)`; and the scan
runner threads the identity into the orchestrator *and its handlers*, so every line a
scan execution writes names its requester. The identity is stored on the scan
(`stats["requested_by"]`, and the queue row's `requested_by` in distributed mode) and in
the report's scope section (`requested_by`, report schema 1.3).

## 220.6 — Reports carry the requester (schema 1.3)

`ScopeMethodology` gains an optional `requested_by`; `build_report_for_scan` reads it from
the scan stats and the Markdown scope section renders it. `REPORT_SCHEMA_VERSION` moves to
`1.3` with `report-schema-1.3.json`, following the S15 pattern (extend the versioned
schema, never hand-edit rendered output).

## 220.7 — SCIM/LDAP: designed, not built (REQ-IDAM-005)

Provisioning is a P2 requirement to *design* the interface so the schema does not churn
later. The design note lives at `docs/scim-ldap-interface.md`: the user/group/role model
maps onto the three existing roles without a fourth table, and the eventual write path is
the same `service_accounts`/`auth_sessions` state a login produces — a SCIM client would
push users and group memberships, not credentials. No endpoint is added in S17.

## 220.8 — Rejected alternatives

* **A JWT/crypto library dependency.** Would be one line in `pyproject.toml`, but the
  default install is deliberately dependency-light and the verifier is ~150 lines with
  an exhaustive negative suite. Revisit if ECDSA/EdDSA providers become mandatory.
* **Storing the raw ID token in the session cookie.** Phishing/replay surface and a
  credential in the browser; the opaque session token (hashed at rest) is the only thing
  the client holds.
* **Mapping IdP groups onto a new role vocabulary.** The three roles are load-bearing
  (ROLE_RANK, every route dependency); group→role binds onto them (REQ-IDAM-002).
* **Hard-deleting a rotated key.** Loses the audit lineage that makes rotation reviewable.
* **Trusting the token without the nonce check.** The nonce is what binds a token to *this*
  login; without it a replayed token from another flow is accepted.
