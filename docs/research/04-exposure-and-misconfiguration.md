# Chapter 4 — Exposure and Misconfiguration Discovery

> **Owner:** Detection group · **Last verified:** 2026-11-05 · **Review interval:** 365 days

The M4 surface: things that are reachable and should not be. Every method is a read — a
request for a well-known path, a header, a policy record or a file — and the finding is the
observation itself. The default-credential method is the only one that authenticates, and it
does so exactly once per candidate pair with the supplied read-only account.

## Methods

### 1. `.env` and dotfile exposure

Requesting the dotfiles that deployment tooling leaves behind (`.env`, `.env.local`,
`.gitignore`, `.htaccess`, `.htpasswd`, `.DS_Store`) for a response that is a file rather than
a generic page.

### 2. VCS metadata exposure

Requesting `.git/HEAD`, `.git/config`, `.svn/entries` and equivalent metadata, which allows a
repository to be reconstructed by a reader who should not have it.

### 3. Backup and archive file discovery

Deriving backup names from the host and application names (`index.php~`, `app.zip`,
`db.sql.gz`, `backup.tar.gz`) and checking for a served file.

### 4. JavaScript source map exposure

Requesting the `.map` sibling of a served bundle, which recovers the original sources,
comments and internal endpoints behind a minified build.

### 5. API documentation exposure

Looking for Swagger UI, OpenAPI documents, Redoc, GraphiQL and API Blueprint files that
describe the full operation set.

### 6. Verbose error and stack-trace exposure

Triggering an error and checking whether the response carries a stack trace, a framework
version, a file path or a SQL fragment.

### 7. Debug endpoint discovery

Enumerating the framework-specific debug routes (`/_debug`, `/phpinfo.php`, `/__debug__/`,
`/trace`) that ship enabled in development profiles.

### 8. Spring Boot Actuator exposure

Checking the actuator endpoints (`/actuator/env`, `/actuator/heapdump`, `/actuator/mappings`)
for an unauthenticated readable response.

### 9. Directory listing detection

Requesting directories whose index is auto-generated, which turns an intended file share
into a browsable subtree.

### 10. Default credential checking

Trying the documented, shipped default pairs for a detected product, once each, with a
read-only account. Never a wordlist: default credentials are a configuration defect, and a
wordlist is credential theft.

### 11. Administrative dashboard exposure

Checking for the management interfaces (Kibana, Grafana, Jenkins, phpMyAdmin, Adminer) that
are reachable without authentication from the scanned scope.

### 12. Datastore management interface exposure

Checking for the web consoles of databases, queues and caches that were meant to stay on an
internal interface.

### 13. Object storage bucket exposure

Testing a scoped bucket for anonymous listing and anonymous object read, which is the
difference between a public website asset and a data breach.

### 14. Client-side secret exposure

Scanning shipped scripts and HTML for API keys, tokens and connection strings that are
readable by any visitor.

### 15. Private key and certificate exposure

Checking for served `.pem`, `.key`, `.p12`, `.pfx` and `.keystore` files, and for certificates
whose private half is served beside them.

### 16. Security header configuration review

Reviewing the header set for correctness rather than presence: an HSTS value that excludes
subdomains, a CSP that allows `unsafe-inline`, a permissive `Permissions-Policy`.

### 17. TLS configuration review

Reviewing the negotiated configuration for weak protocol versions, export and NULL ciphers,
missing forward secrecy and a certificate chain that does not validate.

### 18. Cookie flag audit

Checking `Secure`, `HttpOnly`, `SameSite`, `Domain` and `Path` on every cookie the
application sets, weighted by what the cookie carries.

### 19. CORS configuration review

Reviewing the static CORS configuration for wildcard-with-credentials and for the reflection
of arbitrary origins.

### 20. Email authentication record review

Reviewing SPF, DKIM selector presence, DMARC policy, MTA-STS and TLS-RPT, which are defensive
configuration findings read straight from DNS.

### 21. WebDAV verb exposure

Checking whether `PROPFIND`, `MKCOL`, `PUT` or `DELETE` are enabled on a public path, without
issuing a write verb.

### 22. Legacy service and endpoint exposure

Looking for the old paths a migration left routed: `/cgi-bin/`, `/server-status`,
`/webmail`, a deprecated API version.

### 23. `robots.txt` and sitemap analysis

Reading the exclusion list as an inventory of what the operator considered sensitive, then
checking whether those paths are actually protected.

### 24. Hidden endpoint discovery

Deriving candidate paths from the application's own scripts, documents and archives, rather
than brute-forcing a wordlist.

### 25. Staging and pre-production exposure

Detecting pre-production hosts that resolve publicly (`staging.`, `uat.`, `dev.`, `test.`)
and carry no authentication.

### 26. Cloud metadata endpoint reachability

Confirming whether an application can be induced to reach the instance metadata address,
which is the pivot from an SSRF to cloud credentials. Reachability only: no credential is
read.

### 27. WordPress surface enumeration

Enumerating the CMS surface: version disclosure, plugin and theme inventory, XML-RPC,
the REST user route and the login throttling policy.

### 28. User enumeration

Detecting an interface that distinguishes a valid account from an invalid one through
response content, status or timing.

### 29. Unauthenticated API access audit

Comparing each documented operation against what is reachable with no credential, which
finds the endpoint that was added without its authorisation decorator.

### 30. Path alias and rewrite traversal

Testing whether a web server's alias or rewrite rule allows a path to escape its intended
root, using a benign in-tree file as the differential target.
