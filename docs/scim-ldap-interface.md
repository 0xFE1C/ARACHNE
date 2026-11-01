# SCIM 2.0 / LDAP provisioning interface — design note (S17, REQ-IDAM-005)

Status: **design only** (REQ-IDAM-005, P2). No endpoint ships in S17. This note fixes the
data model and wire contract so that adding provisioning later is a route plus a store
adapter, not a schema migration.

Scope: how an identity provider *provisions* users and groups into ARACHNE, as opposed to
how it *authenticates* them (OIDC, REQ-IDAM-001 — implemented in S17). Provisioning is
optional in both directions: a deployment can keep creating memberships by hand
(`ARACHNE_API_KEYS`, `/api/v1/service-accounts`) and never enable it.

---

## 1. What already exists and must not churn

The identity model S17 established is deliberately small:

| Concept | Table / type | Notes |
|---|---|---|
| Human login | `auth_sessions` row (not a user table) | minted per OIDC login; identity claims come from the IdP every time |
| Machine credential | `service_accounts` row | hashed secret, `owner` (the human), optional expiry, rotation lineage |
| Role | the three ranked roles `viewer < scanner < admin` | `ROLE_RANK`; every route depends on them |
| Group → role | `SsoSettings.group_roles` (`group:role` entries) | evaluated at login, deny-by-default |

There is intentionally **no `users` table**: a user exists only as an IdP subject, and
ARACHNE derives the principal from the token at login. That is the property provisioning
must preserve — the IdP stays the source of truth for *who exists* and *which groups they
are in*; ARACHNE stores only what it needs to authorise and attribute.

## 2. Target model (what provisioning would add)

One new table, `provisioned_principals` (or a nullable `subject` extension of
`auth_sessions`; both are compatible with the endpoints below):

| Column | Purpose |
|---|---|
| `subject` (unique) | the IdP `sub` (immutable, the join key) |
| `user_name` / `emails` | SCIM `userName` and primary email |
| `display_name` | SCIM `displayName` |
| `active` | deprovisioning flag (never a hard delete) |
| `groups_json` | group ids the IdP last asserted for this user |
| `project_slug` | optional tenant binding, the same slug `ApiKey.project` uses |
| `updated_at`, `meta_json` | concurrency/versioning (SCIM `meta.version`, ETags) |

**Role remains derived, not stored per user**: the effective role is
`SsoSettings.role_for(groups)` — the same function the login path calls. Provisioning a
group membership therefore changes the *next* login's role with no write to an
authorisation column, and a group removed at the IdP revokes on the next login. (If a
deployment needs immediate revocation without waiting for re-login, the optional
`auth_sessions.last_seen_at`/expiry is the lever: sessions are short-lived and can be
revoked by subject.)

## 3. SCIM 2.0 (RFC 7643/7644) contract

Base path `/api/v1/scim/v2`, authenticated **exclusively by a service account** with the
`admin` role (a provisioner key created via `POST /service-accounts`, rotated like any
other). SCIM clients send the key in `Authorization: Bearer <secret>`; the credential
store already accepts the same secret through `X-API-Key`, so this is a header alias, not
a new credential type.

| Endpoint | Method | Behaviour |
|---|---|---|
| `/Users` | `GET` `POST` | list (filter/startIndex/count) / create; `POST` is idempotent on `userName` |
| `/Users/{id}` | `GET` `PUT` `PATCH` `DELETE` | `DELETE` sets `active=false` (soft), never deletes the row |
| `/Groups` | `GET` `POST` | list / create; members are subject values |
| `/Groups/{id}` | `GET` `PUT` `PATCH` `DELETE` | membership changes update `groups_json` for affected subjects |
| `/ServiceProviderConfig` | `GET` | capabilities: `patch`, `filter`, `etag`; `bulk` unsupported |
| `/ResourceTypes`, `/Schemas` | `GET` | minimal static documents |

Attribute mapping (SCIM → ARACHNE):

| SCIM | ARACHNE |
|---|---|
| `userName` | `emails[primary]`, else `userName` — the audit display |
| `externalId` | stored verbatim (the IdP's correlation id) |
| `active=false` | principal inactive; existing sessions revocable; **not** a key revoke |
| `Groups.value` (id) + `display` | matched against `SsoSettings.group_roles` by `display` |
| `meta.version` | optimistic concurrency (`If-Match`), backed by `updated_at` |

Errors use the SCIM error envelope (`schemas`, `status`, `detail`) with the standard
`400/401/403/404/409/429`. Rate limiting is the API's existing per-identity bucket.

## 4. LDAP (RFC 4510) contract

LDAP is a **read** integration: ARACHNE binds with a service DN and searches a configured
base, against the same derived model.

| Setting | Meaning |
|---|---|
| `ARACHNE_LDAP_URL` | `ldaps://…` (TLS required except loopback) |
| `ARACHNE_LDAP_BIND_DN` / `_PASSWORD` | the search account (secret, env-only) |
| `ARACHNE_LDAP_BASE_DN` | search root |
| `ARACHNE_LDAP_USER_FILTER` | e.g. `(&(objectClass=person)(uid={user}))` |
| `ARACHNE_LDAP_GROUP_FILTER` | e.g. `(&(objectClass=group)(member={dn}))` |
| `ARACHNE_LDAP_GROUP_ATTR` | attribute holding the group name mapped by `group_roles` |

A sync job (cron or the S20 scheduler) pages `(objectClass=person)` under the base,
upserts `provisioned_principals` by a stable attribute (`entryUUID`/`objectGUID`), and
derives groups from `memberOf` or the group filter. Writes (create/modify/delete) are
**out of scope**: ARACHNE never modifies the directory. LDAP authentication (bind as the
user) is explicitly not implemented — OIDC is the authentication path; LDAP is a
provisioning feed.

## 5. Safety and audit

* Provisioning changes are administrative events: each write records
  `service_account.changed`-style audit metadata under a `provisioning.changed` action
  (added with the feature), with the acting provisioner key and its owner — the same
  "user X via key Y" actor the rest of S17 produces.
* A provisioning key is an `admin` service account; it can create **no** scan and its
  secret is hashed/rotatable like every other key.
* `DELETE` is soft (`active=false`) to preserve attribution of historical scans; a hard
  purge is a separate retention concern (area `DATA`, S20).
* Deny-by-default is unchanged: provisioning a user into no group grants no role, exactly
  as an unmapped OIDC login is refused today.

## 6. Migration path (why this avoids churn)

1. Add `provisioned_principals` (one migration; no change to `service_accounts`,
   `auth_sessions`, `scans` or `audit_log`).
2. Add `/api/v1/scim/v2` routes in a new `scim_routes` module; reuse `CredentialStore` and
   `SsoSettings.role_for` unchanged.
3. Make the login path prefer a provisioned principal's stored groups over fresh claims
   only if a deployment opts in (`ARACHNE_SCIM_AUTHORITATIVE=true`); otherwise claims win
   and provisioning is a directory mirror.

None of these steps changes an existing table's shape or the three-role vocabulary, which
is the point of designing now.

## 7. Open questions for the owner (recorded, not blocking)

* Should tenant binding (`project_slug`) be provisionable per user, or stay a key
  attribute? (Current keys bind tenants; users do not.)
* Is immediate revocation required on group removal, or is next-login sufficient
  (session lifetime `ARACHNE_SSO_SESSION_MAX_AGE`)?
* Does the target directory expose stable UUIDs (`entryUUID`/`objectGUID`) for all people?
  Without one, `userName` is the join key and rename handling must be specified.