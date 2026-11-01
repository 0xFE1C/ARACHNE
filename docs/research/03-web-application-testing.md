# Chapter 3 — Web Application Vulnerability Testing

The M3 surface. Each method pairs a detection with a *proof* that stays inside the proof
ladder: a differential oracle (the response differs when the input differs) is the default,
an out-of-band callback is L2 and opt-in, and a one-shot echoed nonce is the strongest thing
this tool will do (L3). Nothing here writes to, persists in, or exfiltrates from a target.

## Methods

### 1. SQL injection detection

Boolean, time-based and error-based differential oracles against parameters, headers and
cookies, with the database never dumped: the finding is the proof that the query changed
meaning, not the data it could have returned.

### 2. NoSQL injection detection

Operator injection (`$ne`, `$gt`, `$where`) and type-confusion probes against document-store
backed APIs, detected through response differentials.

### 3. Cross-site scripting detection

Reflected, stored and DOM-context detection using a non-executing marker where possible and
a benign, self-owned callback where the context cannot be proven without it.

### 4. Cross-site request forgery audit

Reviewing state-changing endpoints for anti-CSRF tokens, `SameSite` policy and origin
enforcement.

### 5. Server-side request forgery probing

Causing the application to request a URL the scanner controls, to prove that a
user-supplied URL reaches the server's request path. The controlled endpoint is the
scanner's own; internal ranges are never traversed.

### 6. Server-side template injection

Template-expression differentials that distinguish a rendered expression from a literal
string, followed by an out-of-band callback for confirmation.

### 7. XML external entity injection

Entity-expansion probes against XML parsers, confirmed by a callback to the scanner, never by
reading a local file's contents.

### 8. OS command injection detection

Separator and substitution injection with a time-based differential, and the one-shot
`echo arachne-<nonce>` proof at L3 where a callback cannot be observed.

### 9. Insecure deserialisation audit

Identifying serialised-object parameters and testing whether the parser accepts an altered
type tag, with a benign payload class that proves deserialisation without executing anything.

### 10. Unrestricted file upload audit

Checking whether an upload accepts a content type or extension outside its declared set, and
whether the stored object is served back with an active type. No webshell is ever uploaded.

### 11. Path traversal detection

Traversal oracle against file-serving parameters, using a differential on a known-benign
in-tree file rather than a sensitive target file.

### 12. Directory traversal with encoded forms

The same oracle with single, double and overlong encodings, plus the platform-specific
separators a naive filter misses.

### 13. Local and remote file inclusion

Testing whether an include parameter resolves a local path or a remote URL, confirmed by a
callback rather than by reading the file.

### 14. Open redirect detection

Following a redirect parameter to a destination the scanner owns, which proves the
redirection without sending a user anywhere.

### 15. CRLF and header injection

Testing whether user input reaches a response header or a log line, proved by a differential
in the returned header set.

### 16. HTTP request smuggling

CL.TE, TE.CL and TE.TE desynchronisation probes with a bounded, self-contained second
request. Detection only: no request is used to reach another user's session.

### 17. Web cache poisoning audit

Reviewing unkeyed inputs and cache-key construction, and confirming a poisonable response
with a harmless marker rather than a live payload.

### 18. Insecure direct object reference

Comparing a resource that the test account may read against a neighbouring identifier to
prove that authorisation is absent. The scanner never reads a record it was not authorised
to read beyond the identifier differential.

### 19. Authentication and session management

Reviewing login throttling, lockout, password policy surfaces, session fixation, logout
invalidation and session lifetime.

### 20. JWT implementation audit

Checking algorithm confusion, `alg: none` acceptance, signature verification, claim
validation and key handling.

### 21. OAuth 2.0 flow audit

Reviewing redirect-URI validation, state handling, PKCE use, token binding and scope
enforcement.

### 22. SAML assertion audit

Reviewing signature coverage, XML canonicalisation, audience and recipient validation, and
replay protection.

### 23. CORS policy audit

Testing which origins a credentialed cross-origin request is allowed from, including the
reflection and null-origin cases.

### 24. Security response header review

Checking for the presence and correctness of HSTS, CSP, X-Content-Type-Options,
Referrer-Policy, frame-ancestors and Permissions-Policy.

### 25. HTTP parameter pollution

Supplying the same parameter twice to detect which value the application honours and whether
a filter and the business logic disagree about it.

### 26. Mass assignment audit

Submitting fields the interface does not display, to detect an object mapper that binds
request bodies directly onto privileged model attributes.

### 27. Prototype pollution detection

Injecting `__proto__`/`constructor` keys through JSON and query parsers, detected by a
differential in a later response rather than by executing a script.

### 28. Second-order injection

Storing a marker through one interface and observing it in another, which is how an
input-filtered write path is proven to have an unfiltered read path. Not implemented: the
method needs a second interface under the same scope and a persistence step the current
proof ladder does not model.

### 29. Race condition and TOCTOU probing

Issuing a small, bounded set of simultaneous requests against a state transition to detect a
check-then-use window. Bounded by design: volume is the tool, and abuse of volume is not.

### 30. Business logic abuse testing

Testing whether a workflow enforces its own invariants: quantity limits, price integrity,
step ordering and re-use of a single-use token.

### 31. API surface enumeration

Collecting the operations an API exposes from its documentation, its specification and its
observed behaviour, so the audit covers the API and not only the UI's call set.

### 32. GraphQL endpoint audit

Introspection, depth and complexity limits, alias-based batching, field-level authorisation,
and whether the resolver enforces the same checks as the equivalent REST path.

### 33. WebSocket handshake and message audit

Origin enforcement on the upgrade, authentication binding to the socket, and message-level
injection into the application's own protocol.

### 34. Subdomain takeover detection

For each CNAME, checking whether the pointing target still claims the name. Read-only: the
finding is that a provider responds with a claimable-unclaimed error, and no resource is ever
registered.

### 35. Rate limiting and anti-automation review

Confirming that authentication, enumeration and expensive endpoints enforce a limit, and that
the limit is per-identity rather than per-connection.
