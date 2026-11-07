# ARACHNE Operator Guide

> **Owner:** Operations · **Last verified:** 2026-11-05 · **Review interval:** 180 days

This guide is task-oriented: it tells you how to install, configure and operate the ARACHNE
scanner that lives in this repository root. It documents only what the code actually
does. Every command was run against the shipped build (`arachne --version` → `0.1.0`) and
every environment variable below is read by `src/arachne/core/config.py`
(`Settings.from_env`) unless it is explicitly listed in
[§12 "Variables read outside `core/config.py`"](#12-variables-read-outside-coreconfigpy).

> **Responsible use.** ARACHNE is a defensive security tool for scanning **targets you own
> or are explicitly authorized to test**. Unauthorized scanning of systems you do not own
> may violate law and policy (e.g., computer-misuse statutes). ARACHNE enforces
> authorization gates and refuses to operate without a declared, attested scope; operators
> remain responsible for complying with the legal and contractual terms that govern their
> use. ARACHNE detects and reports — it does not exploit, weaponize, or maintain access, and
> it contains no functionality for launching attacks against third parties.

See also: [README](../README.md) · [Plugin Developer Guide](plugin-developer-guide.md) ·
[ADRs](adr/).

---

## 1. Install

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e .
arachne --version        # prints the runtime version, e.g. 0.1.0
arachne info             # effective configuration, secrets redacted
```

Python **3.11+** is required (3.12 recommended; CI runs 3.11 and 3.12).

### Optional extras

`pyproject.toml` declares two extras:

| Extra | Install | Contents |
|---|---|---|
| `dev` | `pip install -e ".[dev]"` | pytest, pytest-asyncio, pytest-cov, mypy, ruff, types-PyYAML, jsonschema, vcrpy |
| `audit` | `pip install -e ".[audit]"` | `pip-audit` (dependency hygiene, runs in its own CI step) |

The scanner's runtime dependencies are `httpx`, `pydantic` (v2), `fastapi`, `uvicorn`,
`typer`, `jinja2`, `sqlalchemy`, `alembic` and `pyyaml`. Everything else (nmap,
`testssl.sh`/`sslscan`, WeasyPrint/headless browsers, Trivy/Syft/Grype-class tools) is
**optional**: the checks have a built-in fallback and run with nothing extra installed.

> **Note (doc/code check).** A mypy override in `pyproject.toml` refers to "the optional PDF
> backend (extra `pdf`)", but no `pdf` extra is declared — the built-in PDF renderer is
> dependency-free and always available.

### Initialise the evidence store

```bash
arachne db upgrade       # apply Alembic migrations (head) to the SQLite file
arachne db current       # applied vs. head revision; exits 1 when out of date
arachne db tables        # list the evidence-store tables
```

---

## 2. Configure

Everything comes from the **environment** — there is no configuration file format (so no
secret can be committed). `.env.example` in the repository root is a documentation template
only; ARACHNE reads the process environment.

Two gates are always in play:

* the **scope gate** — a target must be declared in the target definition *and* fit the
  optional deployment allowlist (F-01-02);
* the **authorization gate** — a **live** scan refuses to start without a complete,
  unexpired attestation covering every target (F-01-09, F-08-05).

`arachne scan --dry-run` needs neither gate: it is pure planning.

### 2.1 Safety, scope and planning

| Variable | Default | Meaning |
|---|---|---|
| `ARACHNE_DATABASE_URL` | `sqlite:///arachne.db` | Evidence-store URL (Postgres-ready). |
| `ARACHNE_SCOPE_HOSTS` | *(empty)* | Deployment allowlist of exact hosts; every declared target must fit inside it. |
| `ARACHNE_SCOPE_DOMAINS` | *(empty)* | Deployment allowlist of domains (apex + subdomains). |
| `ARACHNE_SCOPE_NETWORKS` | *(empty)* | Deployment allowlist of CIDR ranges. |
| `ARACHNE_SCOPE_URL_PREFIXES` | *(empty)* | Deployment allowlist of URL prefixes. |
| `ARACHNE_SCOPE_REFS` | *(empty)* | Deployment allowlist of Git/cloud references (`aws:*`). |
| `ARACHNE_SCOPE_EXCLUDE_HOSTS` / `_DOMAINS` / `_NETWORKS` / `_URL_PREFIXES` / `_REFS` | *(empty)* | Exclusions; always win over any allow. |
| `ARACHNE_ALLOW_PRIVATE_IPS` | `false` | Permit RFC1918/ULA targets. |
| `ARACHNE_ALLOW_LOOPBACK` | `false` | Permit loopback targets (lab fixtures, tests). |
| `ARACHNE_ALLOW_LINK_LOCAL` | `false` | Permit link-local targets (includes cloud metadata IPs). |
| `ARACHNE_REDACTION_ENABLED` | `true` | Redact secrets at evidence-capture time. Turning this off weakens every downstream guarantee; leave it on. |
| `ARACHNE_PLAN_ASSUMED_SUBDOMAINS` | `0` | Dry-run estimate assumption, printed with the plan. |
| `ARACHNE_PLAN_MAX_HOSTS_PER_NETWORK` | `256` | Cap on the host count estimated for one range. |

An empty deployment scope means "no extra restriction"; the target definition's own
declared scope is still enforced deny-by-default.

### 2.2 HTTP client: rate limits, timeouts, capture

| Variable | Default | Meaning |
|---|---|---|
| `ARACHNE_RATE_LIMIT_PER_HOST` | `5` | Requests/second per target host. |
| `ARACHNE_RATE_LIMIT_PER_HOST_BURST` | `5` | Per-host burst capacity. |
| `ARACHNE_RATE_LIMIT_GLOBAL` | `20` | Requests/second across all targets. |
| `ARACHNE_RATE_LIMIT_GLOBAL_BURST` | `20` | Global burst capacity. |
| `ARACHNE_HTTP_TIMEOUT_S` | `15` | Request timeout, seconds. |
| `ARACHNE_HTTP_CONNECT_TIMEOUT_S` | `5` | Connect timeout, seconds. |
| `ARACHNE_HTTP_MAX_REDIRECTS` | `5` | Redirect hops (each one re-validated). |
| `ARACHNE_HTTP_MAX_BODY_BYTES` | `65536` | Response body retained as evidence. |
| `ARACHNE_HTTP_RETRIES` | `1` | Retries for transient failures (never bypasses rate limits). |
| `ARACHNE_HTTP_USER_AGENT` | `ARACHNE/0.1 (+https://localhost/arachne) defensive-security-scanner` | User-Agent header. |
| `ARACHNE_HTTP_VERIFY_TLS` | `true` | Verify server certificates. |
| `ARACHNE_HTTP_FOLLOW_REDIRECTS` | `true` | Follow redirects by default. |
| `ARACHNE_HTTP_FIXTURES` | *(unset)* | Replay recorded responses (a dir or file) instead of the network — see [§10](#10-offline-demo-walkthrough). |

### 2.3 Logging and audit

| Variable | Default | Meaning |
|---|---|---|
| `ARACHNE_LOG_LEVEL` | `INFO` | Structured log level. |
| `ARACHNE_LOG_JSON` | `true` | JSON logs. |
| `ARACHNE_AUDIT_LOG_PATH` | *(unset)* | Also append audit events to this JSONL file. |
| `ARACHNE_ACTOR` | `cli` | Actor recorded on audit events and operator feedback. |

### 2.4 Passive OSINT providers (M1)

Passive reconnaissance is **off by default**: nothing contacts a third party unless
`ARACHNE_OSINT_ENABLED=true`, and then only the providers you name.

| Variable | Default | Meaning |
|---|---|---|
| `ARACHNE_OSINT_ENABLED` | `false` | Master switch for passive OSINT. |
| `ARACHNE_OSINT_PROVIDERS` | `crtsh,circl,wayback,commoncrawl,internetdb` | Which sources may be contacted; the OSINT client's scope is exactly these hosts. Known providers: `crtsh`, `circl`, `wayback`, `commoncrawl`, `internetdb`, `github`, `vulners`, `dns`, `search`. |
| `ARACHNE_OSINT_SEARCH_URL` | *(unset)* | Search API for the dork sweep and email harvesting (`{query}`/`{limit}` placeholders). |
| `ARACHNE_OSINT_FIXTURES` | *(unset)* | Replay recorded OSINT responses instead of the network. |
| `ARACHNE_OSINT_EXTRA_HOSTS` | *(empty)* | Additional hosts the OSINT client may contact (e.g. a private mirror). |
| `ARACHNE_OSINT_REQUEST_BUDGET` | `60` | Maximum third-party requests per scan; exhausting it is recorded, not fatal. |
| `ARACHNE_OSINT_MAX_RESULTS` | `100` | Result cap per check. |
| `ARACHNE_OSINT_MAX_ASSETS` | `500` | Asset cap per check. |
| `ARACHNE_OSINT_DORK_CORPUS` | *(bundled)* | Path to your own dork corpus (F-09-04). |
| `ARACHNE_OSINT_COMMONCRAWL_INDEX` | `CC-MAIN-2024-51` | Pinned Common Crawl crawl for the web-archive harvest check. |
| `ARACHNE_GITHUB_TOKEN` | *(unset)* | Enables the opt-in `m1.code-secret-mining` check; a `SecretStr`, never logged. |
| `ARACHNE_VULNERS_API_KEY` | *(unset)* | Optional online CVE/EPSS enrichment for `m2.cve-correlate`. |

A provider that needs a credential is only contacted when that credential is set; otherwise
its host is left out of the OSINT scope so a lookup is a refusal, not a failed request.

### 2.5 Network probes (M2)

M2 contacts the target directly, so F-01-09 gates every M2 check except the offline
`m2.cve-correlate`: they require `--active-checks` **and** an authorized attestation.

| Variable | Default | Meaning |
|---|---|---|
| `ARACHNE_NET_MAX_PORTS` | `100` | Top-N ports of `templates/m2/ports.yaml` a scan considers. |
| `ARACHNE_NET_MAX_HOSTS` | `64` | Per-unit host cap. |
| `ARACHNE_NET_CONCURRENCY` | `24` | Simultaneous network probes. |
| `ARACHNE_NET_CONNECT_TIMEOUT_S` | `3` | Per-connection connect timeout. |
| `ARACHNE_NET_READ_TIMEOUT_S` | `2` | Read timeout. |
| `ARACHNE_NET_BANNER_WAIT_S` | `0.75` | Short window for an unprompted banner. |
| `ARACHNE_NET_MAX_READ_BYTES` | `8192` | Bytes read from one probe. |
| `ARACHNE_NET_ALLOW_UDP` | `false` | Deployment-level opt-in for UDP probes (SNMP, BACnet) on top of the per-check opt-in. |
| `ARACHNE_NET_NMAP_ENABLED` | `true` | Use `python-nmap` for port/service detection when installed. |
| `ARACHNE_NET_NMAP_TIMEOUT_S` | `120` | nmap timeout. |
| `ARACHNE_NET_TLS_TOOL` | *(unset)* | External deep-TLS tool (`testssl.sh`/`sslscan`) run *in addition to* the stdlib probe. |
| `ARACHNE_NET_TLS_TOOL_TIMEOUT_S` | `120` | Timeout for that tool. |
| `ARACHNE_NET_TLS_CIPHERS` | *(shipped list)* | Cipher suites the stdlib TLS probe tries one at a time. |
| `ARACHNE_KERBEROS_PACING_S` | `1.5` | Lockout-safe pacing for Kerberos principal enumeration. |
| `ARACHNE_KERBEROS_MAX_NAMES` | `12` | Cap on Kerberos candidate names. |
| `ARACHNE_SMTP_PACING_S` | `0.4` | Lockout-safe pacing for SMTP recipient probing. |
| `ARACHNE_PORT_CATALOG` | *(bundled)* | Replace the shipped port catalogue. |
| `ARACHNE_CVE_INDEX` | *(bundled)* | Replace the shipped offline CVE/EPSS index. |
| `ARACHNE_WORDLISTS_DIR` | *(bundled)* | Replace the shipped wordlists. |

### 2.6 Web-application probes (M3)

M3 sends *payloads* at a target, so all M3 active checks require `--active-checks` and an
authorizing attestation; the opt-in families additionally need their own switch.

| Variable | Default | Meaning |
|---|---|---|
| `ARACHNE_WEB_MAX_PAGES` | `20` | Crawl page cap. |
| `ARACHNE_WEB_MAX_DEPTH` | `2` | Crawl depth. |
| `ARACHNE_WEB_MAX_PARAMS` | `6` | (endpoint, parameter) pairs one oracle probes. |
| `ARACHNE_WEB_MAX_ENDPOINTS` | `200` | Crawl endpoint cap. |
| `ARACHNE_WEB_TIME_DELAY_S` | `3.0` | Blocking sleep a time-based probe asks for. |
| `ARACHNE_WEB_TIME_DELTA_S` | `2.0` | Measured excess over baseline that counts as a positive. |
| `ARACHNE_WEB_HIDDEN_PATHS` | `40` | Hidden-endpoint wordlist entries `m3.api-surface` probes. |
| `ARACHNE_WEB_RATE_PROBES` | `5` | Bounded request count for `m3.rate-limit-audit`. |
| `ARACHNE_WEB_UPLOAD_PROBE` | `false` | Let `m3.upload-audit` store its one inert marker file. |
| `ARACHNE_WEB_FOLLOW_REDIRECTS` | `false` | M3 needs the raw 3xx (open-redirect reads `Location`). |
| `ARACHNE_WEB_SSRF_PROBE` | `false` | Let `m3.ssrf-probe` inject the callback URL. |
| `ARACHNE_WEB_SSRF_CALLBACK` | *(unset)* | Out-of-band callback base on your own infrastructure. |
| `ARACHNE_WEB_SMUGGLING_PROBES` | `4` | Bounded request smuggling probes. |
| `ARACHNE_WEB_RACE_CONCURRENCY` | `8` | Concurrency for the race-condition probe. |
| `ARACHNE_WEB_JWT_MAX_TOKENS` | `4` | JWT variants tried. |
| `ARACHNE_WEB_GRAPHQL_BATCH` | `8` | GraphQL batch size. |
| `ARACHNE_WEB_TAKEOVER_NAMES` | `40` | Subdomain-takeover name candidates. |
| `ARACHNE_WEB_SESSION_COOKIE` | *(unset)* | Operator demo session `Cookie` header. |
| `ARACHNE_WEB_SESSION_B_COOKIE` | *(unset)* | Second identity for the IDOR cross-account differential. |
| `ARACHNE_WEB_AUTH_HEADER` | *(unset)* | Raw `Name: value` auth header (e.g. `Authorization: Bearer ...`). |
| `ARACHNE_WEB_PAYLOADS` | *(bundled)* | Replace the M3 payload/wordlist corpus. |

The three session variables are `SecretStr`s; the HTTP client redacts `cookie`/`authorization`
at capture time, so they never reach evidence.

### 2.7 M4 — Misconfiguration & Exposure

| Variable | Default | Meaning |
|---|---|---|
| `ARACHNE_M4_MAX_PATHS` | `60` | Per-check probe cap. |
| `ARACHNE_M4_MAX_FINDINGS` | `8` | Per-check finding cap. |
| `ARACHNE_M4_MAX_BUCKET_NAMES` | `8` | Bucket-name candidates from one declared domain. |
| `ARACHNE_M4_DEFAULT_CREDENTIALS` | `false` | Allow `m4.default-credentials` (one paced vendor-default attempt per product). Needs the check id *and* `--active-checks`. |
| `ARACHNE_M4_DEFAULT_CREDS_PACING_S` | `1.5` | Pacing between default-credential attempts. |
| `ARACHNE_M4_DEFAULT_CREDS_MAX_ATTEMPTS` | `3` | Per-run product cap. |
| `ARACHNE_M4_METADATA_SSRF` | `false` | Allow `m4.metadata-ssrf` to send the metadata GET through a discovered sink. |
| `ARACHNE_M4_PROBES` | *(bundled)* | Replace the M4 probe corpus/wordlists. |

**Artifact exposure (WP-29, REQ-DET-022).** Twenty-four of M4's checks are the
source-control, CI and infrastructure-artifact family, and they are operated exactly like the
rest of M4: read-only `GET` probes of bounded path inventories, no opt-in, no attestation.
They cover the `.git` reflog and a DVCS configuration or credential store carrying
credentials; the GitHub Actions workflows and the other CI pipeline definitions, plus
credential material inside a served pipeline; Terraform state, plan and dependency-lock
artifacts; the AWS credential file, the cloud CLIs' credential stores and cloud
service-account keys; Compose files, Dockerfiles and the Kubernetes/Helm/Rancher manifests;
vim swap, editor backup and operating-system metadata residue; the package-manager and
container-registry credential configuration and the authorization files (`.htaccess`,
`authorized_keys`); and the environment-file variants, secrets files and framework
configuration files. Three properties are worth knowing when you read a finding from this
family:

* **A refusal is not a finding.** The decoy the requirement names is a server that answers
  every artifact path with its own 404 or a generic error page, and each check requires the
  *artifact's own content* (or a suffix the corpus declares binary) — never a status code,
  and never a word the page happens to carry. A soft 404 that answers `200` and quotes the
  path it was asked for is silent too.
* **Nothing is downloaded to confirm an artifact.** Every request goes through the shared
  client, which reads at most the body limit (`ARACHNE_HTTP_MAX_BODY_BYTES`, 64 KiB) and
  marks the body truncated; the finding records the bytes it captured and that limit. A large
  plan file is reported from its suffix and its answer's type, not from its bytes.
* **Secrets are redacted at capture.** Where an artifact carries credential material, the
  finding names the redactor's *detectors* (`aws-access-key-id`, `github-token`,
  `credentialed-url`, `jwt`, `private-key`) and the key names — never a value. The two checks
  whose whole claim is the credential fire only when a detector fired on the served body.

**Server, platform and runtime configuration (WP-30, REQ-DET-023).** The other twenty-four
checks of M4 are the server and platform family, operated the same way: read-only `GET` probes
of bounded path inventories with no opt-in and no attestation, plus three checks that read the
response headers of the crawl the scan already made and issue no request at all. They cover the
nginx, Apache, IIS and Caddy stock default pages and configuration files (including the Apache
basic-auth `.htpasswd` and the IIS `applicationHost.config`); the machine-readable JSON and XML
directory indexes; the Docker Engine and Podman libpod **version endpoints**; the Kubernetes
Dashboard behind the API-server proxy, the kubelet read-only endpoint, the registry `_catalog`
and the registry dashboards (Harbor, Nexus, Artifactory, Portainer); the ActiveMQ, NATS, EMQX,
RocketMQ, Kafka UI and Pulsar consoles (RabbitMQ stays with `m4.dashboard-exposure`, which
already fingerprints it); and the header, cookie and caching defaults — a `Server` banner that
names a version, the stack headers (`X-Powered-By`, `X-AspNet-Version`), and a session response
a shared cache may store. Four properties matter when you read one of these findings:

* **A default page is not automatically a finding.** Each check requires a `2xx` answer *and*
  content that is the artefact's own; an installation that answers a management path with a
  `401` challenge is reported clean, which is what the hardened decoy proves.
* **A container daemon is asked its version and nothing else.** `m4.docker-api-exposed` and
  `m4.podman-api-exposed` name version endpoints only, never a container list or an inspect:
  issuing a command through a daemon socket is out of scope permanently, and the finding
  records `command_issued: false` so that is checkable from the evidence.
* **A version banner is a signal, not a severity claim.** Per the detection programme's FP-3
  rule the two banner checks ship at `low`, name the header line they read and correlate no
  CVE; raise a severity from them only with a verified vulnerable version range behind it.
* **Nothing is executed or changed.** No server is started, stopped, reloaded or reconfigured,
  no configuration is loaded into anything, and no directory index is expanded beyond the
  entries the answer already carried.

### 2.8 M5 — Cloud, container & supply chain

| Variable | Default | Meaning |
|---|---|---|
| `ARACHNE_M5_MAX_PATHS` | `40` | Per-check probe cap. |
| `ARACHNE_M5_MAX_FINDINGS` | `8` | Per-check finding cap. |
| `ARACHNE_M5_MAX_BUCKET_NAMES` | `8` | Bucket-name candidates from one domain. |
| `ARACHNE_M5_IMDS_PROBE` | `false` | Allow `m5.imds-ssrf` to send the metadata GET. |
| `ARACHNE_M5_VALIDATE_CLOUD_KEYS` | `false` | Allow read-only validation call for a found cloud key. |
| `ARACHNE_M5_IMAGE_SCAN` | `true` | Native container-image scanning: resolve the manifest, fetch the layers in scope, unpack into a temporary directory and match advisories. No external tool. |
| `ARACHNE_M5_IMAGE_MAX_LAYERS` | `64` | Layer cap for one image. |
| `ARACHNE_M5_IMAGE_MAX_LAYER_BYTES` | `67108864` | Compressed cap for one layer. |
| `ARACHNE_M5_IMAGE_MAX_UNPACKED_BYTES` | `268435456` | Total unpacked-byte cap across an image; a layer over it is refused. |
| `ARACHNE_M5_IMAGE_MAX_FILE_BYTES` | `33554432` | Per-member unpacked cap. |
| `ARACHNE_M5_IMAGE_MAX_MEMBERS` | `100000` | Per-image archive-member cap. |
| `ARACHNE_M5_IMAGE_TEMP_DIR` | *(platform temp)* | Directory the image is unpacked into; never the workspace. |
| `ARACHNE_M5_REGISTRY_SCAN` | `false` | Opt in to the external scanner path; it is never the default and never a process. |
| `ARACHNE_M5_DOCKER_SOCKET` | `true` | Probe the local Docker daemon socket in addition to a reachable TCP API. |
| `ARACHNE_M5_IAC_TOOL` | *(unset)* | Optional external IaC scanner (tfsec/checkov). |
| `ARACHNE_M5_SBOM_TOOL` | *(unset)* | External scanner whose report is imported (trivy/grype). |
| `ARACHNE_M5_SBOM_REPORT` | *(unset)* | JSON report the external scanner produced out of band, merged into the native findings. |
| `ARACHNE_M5_MAX_FILE_BYTES` | `262144` | Bytes read from one local artifact. |
| `ARACHNE_M5_MAX_REPO_FILES` | `4000` | Repository file-walk cap. |
| `ARACHNE_M5_PROBES` | *(bundled)* | Replace the M5 probe corpus/wordlists. |

### 2.9 M6 — Automation, post-exploitation & AI-era

| Variable | Default | Meaning |
|---|---|---|
| `ARACHNE_M6_MAX_PATHS` | `40` | Per-check probe cap. |
| `ARACHNE_M6_MAX_FINDINGS` | `8` | Per-check finding cap. |
| `ARACHNE_M6_MAX_FILE_BYTES` | `262144` | Bytes read from one local artifact. |
| `ARACHNE_M6_MAX_REPO_FILES` | `4000` | Repository file-walk cap. |
| `ARACHNE_M6_WEBSHELL_PROBES` | `12` | Served shell-path candidates `m6.webshell-yara` fetches (GET only). |
| `ARACHNE_M6_MAX_GIT_OBJECTS` | `200` | Loose `.git` objects decompressed for history lookups. |
| `ARACHNE_M6_EPSS_FEED` | *(unset)* | FIRST EPSS CSV for offline enrichment. |
| `ARACHNE_M6_KEV_FEED` | *(unset)* | CISA KEV JSON for offline enrichment. |
| `ARACHNE_M6_RESOLVED_VERSIONS` | *(unset)* | Asset/version inventory export. |
| `ARACHNE_M6_LOG_ACCESS` | `false` | Explicit log-access grant (without it, telemetry checks ingest nothing). |
| `ARACHNE_M6_LOG_PATHS` | *(empty)* | Log paths the grant covers. |
| `ARACHNE_M6_DECEPTION` | `false` | Allow `m6.deception-listeners` to read the honeytoken trigger log. |
| `ARACHNE_M6_SIGMA_RULES` | *(bundled)* | Replace the Sigma rule directory. |
| `ARACHNE_M6_LPE_INDEX` | *(bundled)* | Replace the local-privilege-escalation index. |
| `ARACHNE_M6_WEBSHELL_PATHS` | *(bundled)* | Replace the served-shell-path wordlist. |
| `ARACHNE_M6_PROBES` | *(bundled)* | Replace the M6 probe corpus/wordlists. |

### 2.10 Analysis (heuristic engine)

| Variable | Default | Meaning |
|---|---|---|
| `ARACHNE_ANALYSIS_RULES` | *(bundled)* | Replace the heuristic rule corpus. |
| `ARACHNE_ANALYSIS_CORRELATION` | *(bundled)* | Replace the correlation rules/dedupe policy. |
| `ARACHNE_ANALYSIS_NARRATIVE` | *(bundled)* | Replace the narrative templates. |
| `ARACHNE_REMEDIATION_CATALOG` | *(bundled)* | Replace the remediation catalog. |
| `ARACHNE_ANALYSIS_SCORING` | *(bundled)* | Replace the derived-CVSS vector table. |
| `ARACHNE_FP_FILTERS` | *(bundled)* | Replace the placeholder/WAF/login-wall filter corpus. |
| `ARACHNE_FP_THRESHOLDS` | *(bundled)* | Per-check confidence thresholds the FP tuner consults (`templates/fp/thresholds.yaml`). |
| `ARACHNE_SIGNATURE_DIRS` | *(empty)* | Extra template directories loaded alongside the bundled signatures. |
| `ARACHNE_ANALYSIS_VERIFY` | `true` | Re-request verifiable candidates once before accepting them. |
| `ARACHNE_ANALYSIS_VERIFY_HIGH_SEVERITY` | `true` | A high/critical finding must be re-requested before it is accepted as confirmed. |
| `ARACHNE_ANALYSIS_MAX_VERIFICATIONS` | `25` | Bound on verification requests per analysis step. |
| `ARACHNE_MIN_CONFIDENCE` | `55` | Below this a finding is a low-confidence observation. |
| `ARACHNE_CORRELATION_ENABLED` | `true` | Run dedupe + correlation rules after analysis. |
| `ARACHNE_FP_TUNER` | `true` | Apply operator FP feedback to the confidence requirement. |
| `ARACHNE_ANALYSIS_DROP_ON_CONTRADICTION` | `true` | Drop a finding a re-request contradicted. |
| `ARACHNE_ANALYSIS_DROP_ON_PLACEHOLDER` | `true` | Drop a finding that is only a placeholder page. |
| `ARACHNE_ASSET_CRITICALITY` | *(empty)* | `pattern=level` pairs (e.g. `example.com=high`) feeding the OWASP impact term. Levels: `critical|high|normal|medium|low|internal`. |

### 2.11 Report engine

| Variable | Default | Meaning |
|---|---|---|
| `ARACHNE_REPORT_MIN_CONFIDENCE` | `55` | Findings below this are reported as low-confidence observations, separately. |
| `ARACHNE_REPORT_EVIDENCE_LIMIT` | `8192` | Maximum captured body excerpt in a report (the full capture's hash is still recorded). |
| `ARACHNE_REPORT_LOW_CONFIDENCE` | `true` | Keep the low-confidence section in the rendered report. |
| `ARACHNE_REPORT_OWASP_MAP` | *(bundled)* | Replace the CWE→OWASP Top-10 map. |
| `ARACHNE_REPORT_SUMMARY` | *(bundled)* | Replace the executive-summary template corpus. |

### 2.12 AI providers (optional)

The AI layer is optional, explicit and swappable, with the heuristic engine as the anchor
and fallback. With no provider configured, `--engine ai` is refused at plan time (F-03-03).

| Variable | Default | Meaning |
|---|---|---|
| `ARACHNE_AI_CONFIG` | *(unset)* | The provider file (`ai: providers:...`). |
| `ARACHNE_AI_ENGINE` | *(unset)* | Deployment default engine (`ai`/`heuristic`/`hybrid`). |
| `ARACHNE_AI_PROVIDER` | *(unset)* | Default provider for the one-provider shortcut. |
| `ARACHNE_AI_PRIVACY` | `redact` | `local-only` refuses non-local endpoints; `redact` tokenizes URLs/hosts/IPs/emails/credentials; `default` sends evidence as captured. |
| `ARACHNE_AI_MAX_TOKENS_PER_SCAN` | *(unset; 200000 when set)* | Per-scan token budget (0 disables the gate). |
| `ARACHNE_AI_MAX_COST_USD` | *(unset; 1.50 when set)* | Per-scan cost budget (0 disables the gate). |
| `ARACHNE_AI_STAGES` | *(empty)* | Which stages run per candidate. |
| `ARACHNE_AI_RETRIES` | *(unset; 3 when set)* | Retry attempts (transient only), within `[1, 10]`. |
| `ARACHNE_AI_CORRELATE_THRESHOLD` | *(unset; 3 when set)* | Group size that gets an AI compound description (≥ 2). |
| `ARACHNE_AI_AUTHORITATIVE_CHECKS` | *(empty)* | Check ids/modules whose AI verdict replaces the deterministic one. Empty keeps parity. |
| `ARACHNE_AI_PROMPTS` | *(bundled)* | Replace the prompt corpus. |
| `ARACHNE_AI_PRICING` | *(bundled)* | Replace the price table. |
| `ARACHNE_AI_CACHE_DIR` | *(unset)* | Durable analysis cache directory. |

The one-provider shortcut also reads `ARACHNE_AI_BASE_URL`, `ARACHNE_AI_MODEL` and
`ARACHNE_AI_API_KEY_ENV` — see [§12](#12-variables-read-outside-coreconfigpy).

Provider keys are read from the environment by the AI layer and are never logged, stored in
evidence, or written to reports.

**What the AI contributed, and what it cost.** Every analysis row persists an AI provenance
record — origin (`ai`/`heuristic`), provider, model, prompt-template hash, prompt and completion
tokens, the evidence ids the model cited, and the change it made — so an AI row is distinguishable
from a heuristic one without reading the audit trail. Three entry points expose it:

| Command | What it answers |
|---|---|
| `arachne ai provenance --scan 41` | Which provider received how many tokens for this scan, how many rows a model contributed to, and which stages did the work. `--project 3` does the same across a project; `--table` prints it for a terminal. |
| `arachne compliance export --scan 41 --framework iso27001` | The same block, attached to the control-evidence document an auditor already reads (the `ai` key). `null` there means the exporter could not say — never "no AI ran". |
| `python -m arachne.ai.eval --cases tests/eval/fixtures/ai-eval-cases-v1.jsonl --baseline tests/eval/fixtures/ai-eval-baseline-v1.json --check` | Whether a prompt, model-config or stage change regressed the offline evaluation suite. Exit code 1 on a regression beyond the declared 2-point threshold. |
| `python -m arachne.ai.parity --cases tests/eval/fixtures/ai-eval-cases-v1.jsonl --date YYYY-MM-DD` | The provider parity matrix: per adapter and stage, the structured-output mechanism chosen, whether decoding is constrained, and the scores. |

An AI answer that cites no evidence id the finding actually has is refused: the stage is recorded
as a failed stage (`evidence_not_cited`), the deterministic result stands, and the row is not
marked as an AI contribution. That is deliberate — an unciteable AI row is the one thing the
provenance requirement forbids.

### 2.13 REST API and web UI

| Variable | Default | Meaning |
|---|---|---|
| `ARACHNE_API_KEYS` | *(empty)* | API keys as `label:role:secret` entries, `;`-separated. Empty closes the API. |
| `ARACHNE_API_KEYS_FILE` | *(unset)* | Read keys from a file (one per line, `#` comments allowed). |
| `ARACHNE_API_HOST` | `127.0.0.1` | Bind address for `arachne serve`. |
| `ARACHNE_API_PORT` | `8080` | Bind port. |
| `ARACHNE_API_REQUIRE_TLS` | `true` | TLS by default: a non-loopback bind needs a certificate unless `--insecure`. |
| `ARACHNE_API_TLS_CERT` / `ARACHNE_API_TLS_KEY` | *(none)* | Certificate and key (must be set together). |
| `ARACHNE_API_RATE_LIMIT` | `120` | Per-identity requests per minute. |
| `ARACHNE_API_RATE_BURST` | `30` | Per-identity burst capacity. |
| `ARACHNE_API_BASE_URL` | *(none)* | Public base URL used to build report links in webhook cards. |
| `ARACHNE_API_DOCS` | `true` | Serve `/docs` and `/openapi.json`. |
| `ARACHNE_API_CORS_ORIGINS` | *(empty)* | Allowed CORS origins. |
| `ARACHNE_API_TRUSTED_HOSTS` | *(empty)* | Host-header allowlist (DNS-rebinding defense). |
| `ARACHNE_API_SESSION_MAX_AGE` | `43200` | UI session cookie lifetime, seconds. |

For a reference, the file/dir used here is `/run/secrets/arachne-api-keys` in the example
below.

### 2.14 Webhooks

| Variable | Default | Meaning |
|---|---|---|
| `ARACHNE_WEBHOOKS_ENABLED` | `false` | Master switch; each endpoint is configured separately. |
| `ARACHNE_WEBHOOK_SLACK_URL` | *(unset)* | Slack incoming webhook URL. |
| `ARACHNE_WEBHOOK_TEAMS_URL` | *(unset)* | Microsoft Teams webhook URL. |
| `ARACHNE_WEBHOOK_JIRA_URL` / `ARACHNE_WEBHOOK_JIRA_PROJECT` | *(unset)* | Jira base URL and project (issues per finding at/above `min_severity`). |
| `ARACHNE_WEBHOOK_JIRA_USER` / `ARACHNE_WEBHOOK_JIRA_TOKEN` | *(unset)* | Jira credentials. |
| `ARACHNE_WEBHOOK_DEFECTDOJO_URL` / `ARACHNE_WEBHOOK_DEFECTDOJO_TOKEN` | *(unset)* | DefectDojo import endpoint and token. |
| `ARACHNE_WEBHOOK_MIN_SEVERITY` | `high` | Floor for actionable cards and Jira issues. |
| `ARACHNE_WEBHOOK_MAX_FINDINGS` | `25` | Per-notification issue cap. |
| `ARACHNE_WEBHOOK_TIMEOUT_S` | `10` | Delivery timeout. |
| `ARACHNE_WEBHOOK_TEMPLATES` | *(bundled)* | Replace the Slack/Teams/Jira/DefectDojo payload templates. |

### 2.15 Scheduler

| Variable | Default | Meaning |
|---|---|---|
| `ARACHNE_SCHEDULER_STATE` | *(unset; `.arachne/schedules.json`)* | Scheduler state document (operational, safe to delete). |
| `ARACHNE_SCHEDULER_MAX_RUNS` | `4` | Maximum due scans one tick executes. |
| `ARACHNE_SCHEDULER_DIFF` | `true` | Persist a `scans_diff` row per scheduled run. |

### 2.16 Operator secrets ledger

| Variable | Default | Meaning |
|---|---|---|
| `ARACHNE_SECRETS_MANIFEST` | *(unset)* | Path for the encrypted secrets ledger. Unset writes nothing. |
| `ARACHNE_SECRETS_MANIFEST_KEY` | *(unset)* | Passphrase. **Required** when a path is set: the writer refuses an unencrypted manifest. |
| `ARACHNE_SECRETS_MANIFEST_MAX` | `500` | Maximum records retained. |

---

## 3. Run a scan

A **target definition** (F-01-01) is a YAML/JSON document: declared targets (domain, host
pattern, URL, IP, CIDR, Git reference, cloud reference), an exclusion list, an authorization
attestation, and scan options. See [`examples/targets/lab-fixture.yaml`](../examples/targets/lab-fixture.yaml).

### 3.1 Dry run (safe, no network, no database)

```bash
arachne scan --target examples/targets/lab-fixture.yaml --dry-run
arachne scan --target examples/targets/lab-fixture.yaml --dry-run --json
```

The dry run prints the complete plan — scope, attestation status, assets, pipeline steps,
included/withheld checks and an estimated request count — and makes **zero** requests. It
needs no database and no attestation.

### 3.2 Run it

```bash
arachne scan --target examples/targets/lab-fixture.yaml
arachne scan --target examples/targets/lab-fixture.yaml --resume 1   # after a crash
```

State is persisted per step; every request flows through the shared scoped client and one
audit event accompanies every request and refusal.

### 3.3 Select modules and checks

```bash
--enable M1,M4          # comma-separated module ids to enable
--disable M2            # comma-separated module ids to disable
--check m4.default-credentials,m4.metadata-ssrf   # opt-in check ids
--active-checks         # opt in to active checks (the attestation must authorize them)
```

An opt-in check (e.g. `m4.default-credentials`) runs only when named with `--check`, and an
active check named there still needs `--active-checks` **and** an authorizing attestation.

### 3.4 Engine modes

```bash
--engine heuristic      # default: the deterministic engine
--engine ai             # provider calls; refused at plan time if no provider is configured
--engine hybrid
```

### 3.5 CI gate: thresholds and exit codes

```bash
arachne scan --target lab.yaml --fail-on high
```

`--fail-on` (or `ARACHNE_CI_FAIL_ON`, default `none`) is a severity threshold in
`info|low|medium|high|critical|none`. The exit code is (F-07-05):

| Exit | Meaning |
|---|---|
| `0` | clean — no finding at or above the threshold (and, with the gate enabled, no finding at all) |
| `1` | findings exist, all below the threshold |
| `2` | at least one finding at or above the threshold |

### 3.6 The proof ladder (L0–L4, S15)

Every check declares how far it may go to prove a finding (REQ-PROOF-001). The dry run
prints the level next to every check (`[L1]`, `[L2]`…), and an L3/L4 row prints the
attestation it demands:

| Level | Meaning | Gates |
|---|---|---|
| L0 | passive — never touches the target | — |
| L1 | active read-only (the default; all 129 original checks) | active-checks opt-in + attestation |
| L2 | out-of-band: the target connects to ARACHNE's callback service | + `--check` (opt-in), a callback service |
| L3 | one-shot command: exactly one `echo arachne-<nonce>` | + `--check`, `ARACHNE_WEB_RCE_PROBE=true`, **state-change attestation** |
| L4 | minimal reversible state change (INSERT-first, auto-restored) | + `--check`, `ARACHNE_WEB_STATE_PROBE=true`, **state-change attestation** |

The rules the engine enforces (REQ-PROOF-003): an L3/L4 check is never planned unless you
named it with `--check`; a live scan whose plan still contains an L3/L4 check **without**
a `state_changes_authorized: true` attestation is refused and the refusal is audited as
`proof.rejected` (the dry run prints the requirement instead of refusing). An unavailable
capability **downgrades** a check with a recorded note (`proof.downgraded`) — it never
blocks, and no check is ever upgraded above its declaration.

**Out-of-band callbacks (L2).** Run the standalone service and point the scan at it:

```bash
arachne callback-server --host 127.0.0.1 --port 8081 --audit-log audit-callbacks.jsonl
export ARACHNE_WEB_SSRF_CALLBACK=http://127.0.0.1:8081   # + declare this host in scope
export ARACHNE_WEB_SSRF_PROBE=true
arachne scan --target lab.yaml --active-checks --check m3.ssrf-probe,m3.sqli-oob,m3.xxe-oob,m3.cmdi-oob,m3.ssti-oob
```

The service issues single-use `arachne-<scan-id>-<check-id>-<nonce>` tokens, matches each
hit to exactly one finding, rate-limits and audits everything — and never dials out. The
L2 variants are: SSRF (`m3.ssrf-probe`), time-free blind SQLi (`m3.sqli-oob`), OOB XXE
(`m3.xxe-oob`), blind command injection via an execution monitor (`m3.cmdi-oob`) and
template injection (`m3.ssti-oob`).

**Callback hardening (WP-14, REQ-PROOF-019).** A token is not just an unguessable nonce:

* **A per-scan secret authenticates it.** The scanner derives a secret for the scan from
  `ARACHNE_INTEGRITY_KEY` and the token carries a short authenticator over itself
  (`arachne-<scan>-<check>-<nonce>~<mac>`); the callback service derives the same secret, so
  it accepts the scan's own token and refuses one assembled from a leaked nonce. With no
  deployment key there is no secret to derive and the nonce is the authenticator, exactly as
  before — set the key if you want the stronger form.
* **A callback is refused for a scan that is not active**, or whose attestation has expired.
  The standalone service reads the scan row for this (`--no-scan-gate` runs it as a pure
  listener for a deployment that fronts ARACHNE with its own proxy).
* **Single use has a bounded replay window.** A callback that arrives after the token was
  spent is refused and counted as a replay (`proof.oob_replay`, and the probe's `replays`
  count); the first verdict stands and no second hit is recorded. Past the window the token is
  expired and the callback is refused under `proof.oob_refused`. A wrong or missing
  authenticator, an inactive scan and an expired attestation are all `proof.oob_refused`.

**State-change proofs (L3/L4).** With `state_changes_authorized: true` in the attestation:

```bash
export ARACHNE_WEB_RCE_PROBE=true ARACHNE_WEB_STATE_PROBE=true
arachne scan --target lab.yaml --active-checks --check m3.rce-echo,m3.state-marker
```

`m3.rce-echo` executes exactly one allowlisted command (`echo arachne-<nonce>`) — there is
no API that could carry a different command. `m3.state-marker` inserts one marker row into
`arachne_poc` (or the obviously-fake record your sink exposes), verifies it, restores it
and re-verifies the restore; `DELETE`/`DROP`/`TRUNCATE`/`ALTER`/`GRANT`, multi-statement
payloads and identity-store tables are refused in code. The end-of-scan cleanup pass
re-restores anything left, and every change is persisted with the scan (`stats.proof`):
what, where, the before-value, and whether it was restored.

**The residue attestation (WP-14, REQ-PROOF-017).** Every scan — including one that
authorized no state change at all — ends with one artefact stating what it changed and
whether it was put back:

* one entry per state change: the asset, the action, the **hash** of the before-value (never
  the value), the restore outcome (`restored`, `restored-unverified`, `not-restored`,
  `error`) and the timestamp;
* the verdict: `"every state change was restored — zero residue"`, or the count that was not
  restored plus the ledger's repair instructions;
* **signed** with `ARACHNE_INTEGRITY_KEY` when one is configured, and **marked
  `signed: false`** when it is not — an unsigned attestation says so rather than looking
  like a signed one;
* its `hash` is linked into the audit chain (`proof.residue_attested`), and it is stored on
  the scan row (`residue_attestation`, `residue_hash`) and exposed by
  `GET /api/v1/scans/{id}`.

**A scan with non-zero residue is not clean.** It is reported as such (the report shows a
residue warning and the unrestored list), and the attestation audit line carries outcome
`error`. Read it before archiving the scan: `arachne report <scan> --format json` and look at
`residue_attestation`, or `GET /api/v1/scans/<id>`. Repair, then re-run the scan's proof —
never edit the attestation, which is hash- and signature-checked.

---

## 4. Read a report

Findings proven at L2+ carry a **Proof** section — level, method, the callback token, and
the cleanup status ("restored inline and re-verified", or `**NO — repair required**`).
Appendix F lists every state change an L4 proof made (what / where / before / after /
restored); a `restored=no` row is a repair instruction, and the audit trail carries the
matching `proof.repair_required` event (REQ-PROOF-010/013).

```bash
arachne report --scan 12                              # Markdown to stdout (default)
arachne report --scan 12 --format json --output report.json
arachne report --scan 12 --format html --output report.html
arachne report --scan 12 --format pdf --output report.pdf
arachne report --scan 12 --diff-with 7                # persist and render the diff
```

Formats: **`md`** (default), **`html`**, **`json`**, **`pdf`** (`markdown` is an alias of
`md`). The JSON report is machine-readable and schema-versioned (schema `1.0`). HTML and PDF
are rendered from the same immutable DTO, so they cannot drift; the PDF uses a built-in
dependency-free paginator by default (see [§12](#12-variables-read-outside-coreconfigpy) for
the optional external backend).

`--diff-with OTHER` compares an earlier scan with `--scan`, records the
`new`/`fixed`/`regressed`/`recurring` sets in `scans_diff`, and includes the trend in the
rendered report. The command is read-only with respect to findings.

Preview what the current rule corpus would say about a stored scan, without writing
anything:

```bash
arachne analyze --scan 12
arachne analyze --scan 12 --show --json
```

---

## 5. REST API and web UI

One command starts the API and the UI:

```bash
# Loopback development: plain HTTP is fine (no certificate configured).
ARACHNE_API_KEYS='admin:admin:<random-secret>;ci:scanner:<random-secret>;ui:viewer:<random-secret>' \
  arachne serve --host 127.0.0.1 --port 8080
# → web UI at http://127.0.0.1:8080/ui/  ·  OpenAPI docs at /docs  ·  JSON API at /api/v1

# A deployed interface: TLS by default (serve refuses a public address without a certificate).
ARACHNE_API_KEYS_FILE=/run/secrets/arachne-api-keys \
ARACHNE_API_TLS_CERT=/etc/arachne/tls/cert.pem ARACHNE_API_TLS_KEY=/etc/arachne/tls/key.pem \
  arachne serve --host 0.0.0.0 --port 8443

# Loopback-only, plain HTTP, explicitly acknowledged:
arachne serve --host 127.0.0.1 --port 8080 --insecure
```

With no API keys configured, the API refuses every request (closed by default); `serve`
prints a warning saying so. `ARACHNE_API_TLS_CERT`/`_KEY` must be set together.

### Roles and resources

Keys are `label:role:secret`; roles are ordered `viewer` < `scanner` < `admin`. The API is
mounted at `/api/v1`:

| Resource | Verbs | Minimum role |
|---|---|---|
| `/health` | GET | *(none)* |
| `/scans` | GET, POST | viewer / scanner |
| `/scans/{id}` | GET, DELETE | viewer / admin |
| `/scans/{id}/stop` | POST | scanner |
| `/scans/{id}/report` | GET, POST | viewer / scanner |
| `/findings` | GET | viewer |
| `/findings/{id}` | GET, PATCH, DELETE | viewer / scanner / admin |
| `/targets` | GET, POST | viewer / admin |
| `/targets/{id}` | GET, DELETE | viewer / admin |
| `/modules` | GET | viewer |
| `/config` | GET | viewer |
| `/schedules` | GET, POST, DELETE, `/run` | viewer / scanner |
| `/webhooks` | GET | admin |

`POST /scans` admits a scan and runs it in the background; it never scans inline. The web UI
(`/ui/`) provides a dashboard, a report viewer, scan controls, read-only module config and
schedule management, and it renders the same Markdown/JSON as `arachne report`.

---

## 6. False-positive tuner (`arachne fp`)

Four verbs, one learner. Feedback never deletes a finding; it drives a per-check confidence
requirement.

Record feedback for a finding:

```bash
arachne fp mark 42 --note "known test page"            # default: mark as false positive
arachne fp mark 42 --not-fp                            # mark as a true positive
arachne fp mark 42 --status accepted --actor alice     # set an explicit status
```

Inspect the learner table:

```bash
arachne fp stats                     # marks, FP rate, current and suggested thresholds
arachne fp stats --check m4.env-file-probe --json
arachne fp check m4.env-file-probe --asset-kind url  # one key's required confidence
```

Produce (and optionally write) tuned thresholds:

```bash
arachne fp tune                                            # suggestions only
arachne fp tune --minimum-marks 5 --json
arachne fp tune --write templates/fp/thresholds.yaml       # reviewable threshold file
```

The shipped threshold file is `src/arachne/templates/fp/thresholds.yaml` (schema `1.0`, a
`default` plus a per-check `checks` map). Point a deployment at your own with
`ARACHNE_FP_THRESHOLDS`.

> **Note (doc/code check).** The header comment in `templates/fp/thresholds.yaml` says the
> `default` "mirrors `ARACHNE_ANALYSIS_MIN_CONFIDENCE`"; the actual variable is
> `ARACHNE_MIN_CONFIDENCE`.

---

## 7. Coverage tool (`arachne coverage`)

```bash
arachne coverage                                   # human-readable matrix
arachne coverage --json                            # machine-readable
arachne coverage --write coverage_matrix.md        # the G-01 artefact
arachne coverage --include-templates               # also count catalogue references
```

The tool greps `research_ref` values out of `src/arachne/modules` and compares them with the
numbered methods in `docs/research/`. `arachne module coverage` is the same command under the
`module` group. `arachne coverage` reports **148/175 (84.6%)** of the research methods mapped
to checks; the per-chapter breakdown is printed with the matrix.

> **Note.** The generated matrix is committed at `coverage_matrix.md`, and a test fails when
> it goes stale. Refresh it with `arachne coverage --write coverage_matrix.md` after adding a
> check or a `research_ref`.

The module inventory is separate:

```bash
arachne module list            # every module with its checks, versions and flags
arachne module list --json
arachne module list --module M4
```

---

## 8. Scheduling

```bash
arachne schedule add --id nightly --target examples/targets/lab-fixture.yaml \
  --cron '0 3 * * *' --engine heuristic
arachne schedule list
arachne schedule list --json
arachne schedule run                       # run everything due now
arachne schedule run --id nightly           # run one schedule immediately
arachne schedule run --now 2026-11-01T03:00:00
arachne schedule remove nightly
```

Cron is the standard 5-field form (`minute hour day month weekday`). With
`ARACHNE_SCHEDULER_DIFF=true`, each scheduled run compares itself with the previous run of
the same schedule and persists a `scans_diff` row (new/fixed/regressed/recurring). Schedule
state lives in `.arachne/schedules.json` by default (`ARACHNE_SCHEDULER_STATE`).

---

## 9. Webhooks

Webhooks are opt-in and data-driven. Enable the feature, then configure any endpoints (see
[§2.14](#214-webhooks)):

```bash
ARACHNE_WEBHOOKS_ENABLED=true \
ARACHNE_WEBHOOK_SLACK_URL='https://hooks.slack.com/services/...' \
ARACHNE_WEBHOOK_JIRA_URL='https://jira.example.com' \
ARACHNE_WEBHOOK_JIRA_PROJECT='SEC' \
ARACHNE_WEBHOOK_JIRA_USER='arachne' ARACHNE_WEBHOOK_JIRA_TOKEN='...' \
ARACHNE_API_BASE_URL='https://arachne.example.com' \
  arachne serve --host 127.0.0.1 --port 8080
```

A webhook never fails a scan: deliveries are audited, capped by `ARACHNE_WEBHOOK_MAX_FINDINGS`,
and their errors are returned to the caller. A Jira issue is opened per finding at or above
`ARACHNE_WEBHOOK_MIN_SEVERITY`.

---

## 10. Offline demo walkthrough

A complete scan with **no network and no third party**: M1 recon runs against recorded
responses, so the whole pipeline executes offline. Copy-paste from the repository root:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"

# 1. A fresh evidence store for the demo.
export ARACHNE_DATABASE_URL="sqlite:///$(pwd)/demo.db"
arachne db upgrade

# 2. Show the plan — zero requests.
arachne scan --target examples/targets/lab-fixture.yaml --dry-run

# 3. Run the M1 module against recorded responses.
ARACHNE_OSINT_ENABLED=true \
ARACHNE_OSINT_FIXTURES=tests/fixtures/osint \
ARACHNE_HTTP_FIXTURES=tests/fixtures/http \
ARACHNE_OSINT_SEARCH_URL='https://search.example.net/search?q={query}&limit={limit}&format=json' \
  arachne scan --target tests/fixtures/targets/m1-fixture.yaml

# 4. Read the result in every format.
arachne report --scan 1                       # Markdown to stdout
arachne report --scan 1 --format json --output report.json
arachne report --scan 1 --format html --output report.html
arachne report --scan 1 --format pdf  --output report.pdf
```

Every request still goes through the scoped, rate-limited, redacted, audited client — the
transport just reads a recording instead of opening a socket. On the shipped fixtures the
scan records 48 assets and 8 analysed findings (2 medium, 6 low, 2 low-confidence).

A **live** scan of a fixture also works (no `ARACHNE_*_FIXTURES`): the lab fixtures point at
documentation ranges and loopback only, so they need `ARACHNE_ALLOW_PRIVATE_IPS=true`
(RFC 5737 ranges) or `ARACHNE_ALLOW_LOOPBACK=true` (loopback labs) to reach anything.

---

## 11. Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `a live scan would be refused` in a dry run | The target definition has no attestation, or it is expired/incomplete. Add one covering every target (F-08-05). |
| `attestation does not authorize active checks` | Set `active_checks_authorized: true` in the attestation, then pass `--active-checks`. |
| Out-of-scope host never contacted; audit shows `scope.discarded` | The host is neither declared nor inside the deployment allowlist. Declare it in the target definition or add it to `ARACHNE_SCOPE_*`. |
| `refusing to serve ... without TLS` | Binding a non-loopback address needs `ARACHNE_API_TLS_CERT`/`_KEY`; use `--insecure` only for loopback development. |
| API refuses every request | No API keys configured. Set `ARACHNE_API_KEYS` or `ARACHNE_API_KEYS_FILE`. |
| `no AI provider is configured` on `--engine ai` | Set `ARACHNE_AI_CONFIG`, or `ARACHNE_AI_PROVIDER` + `ARACHNE_AI_BASE_URL` + `ARACHNE_AI_MODEL` (+ `ARACHNE_AI_API_KEY_ENV` for a hosted provider). |
| `status: out of date — run arachne db upgrade` | The schema is behind; run `arachne db upgrade`. |
| A check reports itself skipped | It found no applicable asset, its provider is disabled, or a required switch (e.g. `ARACHNE_NET_ALLOW_UDP`, `ARACHNE_M4_DEFAULT_CREDENTIALS`) is off. The skip reason is recorded as evidence. |
| Coverage numbers look stale | Regenerate `coverage_matrix.md` with `arachne coverage --write coverage_matrix.md`. |

Errors from the CLI itself print `error: ...` and exit `2`; a clean CI gate exit is `0`, a
below-threshold gate is `1`, and an at-or-above gate is `2`.

---

## 12. Variables read outside `core/config.py`

A small number of variables are read directly by the layer that owns them rather than by
`Settings.from_env`:

| Variable | Read by | Purpose |
|---|---|---|
| `ARACHNE_AI_BASE_URL` | `ai/config.py` | Base URL for the one-provider shortcut. |
| `ARACHNE_AI_MODEL` | `ai/config.py` | Model name for the one-provider shortcut. |
| `ARACHNE_AI_API_KEY_ENV` | `ai/config.py` | Name of the environment variable holding the provider key (never the key itself). |
| `ARACHNE_CI_FAIL_ON` | `cli/scan.py` | Default CI-gate threshold for `arachne scan`. |
| `ARACHNE_LOCALE` | `i18n/catalog.py` | Default locale for operator-facing text (default `en`). |
| `ARACHNE_PDF_BACKEND` | `report/pdf_backend.py` | PDF backend selection (default `builtin`; `auto` opts in to an external headless engine). |
| `ARACHNE_PROJECT_ROOT` | `cli/main.py` | Locate `alembic.ini`/`migrations/` (container/deployment override). |

## 13. Projects / workspaces (multi-tenancy, F-07-06)

One deployment can serve several customers. A **project** is the tenant boundary:

* it declares the addresses its operator may scan (`scope`), on top of the deployment
  allowlist — a scan is refused when a target falls outside it, even if the deployment
  would allow it;
* targets and scans belong to it, and every list is filtered by it;
* it can carry its own report branding (see §16).

The `default` workspace always exists and owns every row written before S14
(`project_id IS NULL`); it cannot be deleted.

```bash
arachne project create acme --name "Acme Corp" --scope-domains acme.example \
  --scope-hosts 203.0.113.10 --exclude-hosts admin.acme.example
arachne project list
arachne project show acme

arachne scan --target acme.yaml --project acme      # scope-gated by acme's scope
arachne report --scan 7 --project acme

# API: X-Project (or ?project=) selects the tenant; a bound key cannot name another one.
curl -H 'X-API-Key: <secret>' -H 'X-Project: acme' http://127.0.0.1:8080/api/v1/scans
```

Binding a key to a tenant is a fourth field in the key entry:

```
ARACHNE_API_KEYS='acme-admin:admin:<random>:acme;globex-viewer:viewer:<random>:globex'
```

A bound key is refused (403) when it names a different project; a three-field key is
deployment-wide and may name any project. Single-resource routes answer **404** for another
tenant's scan or finding — its existence is not disclosed.

Known limit: the scheduler is deployment-wide, so a scheduled scan runs in the default
workspace.

## 14. CVE/EPSS feed ingestion (F-09-03)

Correlation uses the bundled EPSS/KEV snapshot by default. To use a fresher feed, import it —
ARACHNE validates and normalises it, and the next scan uses it automatically.

```bash
# FIRST EPSS CSV (cve,epss,percentile), CISA KEV JSON, or a CVE JSON/YAML snapshot
arachne feeds import epss-2026-10-29.csv --name epss-2026-10-29
arachne feeds list
arachne feeds show 1 --limit 20
arachne feeds lookup CVE-2021-44228      # merged EPSS + KEV across the active feeds
arachne feeds stats
arachne feeds delete 1
```

The normalised file lands under `ARACHNE_FEEDS_DIR` (default: beside the SQLite database) and
is exactly what `ARACHNE_M6_EPSS_FEED` / `ARACHNE_M6_KEV_FEED` consume, so the environment
does not need to change. The newest feed of each kind is the active one.

Ingestion makes **no network request**: fetching a feed is your job (`curl`), which keeps the
scanner's egress rules intact and works on an air-gapped host. `ARACHNE_FEEDS_MAX_ENTRIES`
bounds one import.

The web UI has the same surface at `/ui/feeds` (paste a document, list/delete artefacts), and
the API at `POST /api/v1/feeds`, `GET /api/v1/feeds/lookup/{cve}`.

## 15. Plugins (F-09-01)

Two families install the same way: check/module plugins register under `arachne.modules`,
report-format plugins under `arachne.report_formats`. Neither requires a core change.

```bash
arachne plugin list                     # installed third-party checks/formats
arachne plugin formats                  # every renderable format, built-in and installed
arachne plugin marketplace              # the versioned catalogue, flagged installed/available
arachne plugin marketplace --search m4

# A local path, a wheel/sdist, or a git URL. --dry-run prints the exact pip command.
arachne plugin install examples/plugins/arachne_example_report_plugin --no-build-isolation
arachne plugin install git+https://host/org/arachne-plugin.git
arachne plugin install ./my-plugin --dry-run

arachne report --scan 7 --format example-csv --output findings.csv
```

`--no-build-isolation` is for an offline host that already has the build backend (the
container image ships `hatchling`/`setuptools`). A source that begins with `-` is refused (pip
would read it as an option), and a directory without `pyproject.toml`/`setup.py` is refused
with the reason. After installing, restart long-lived processes (`arachne serve`, a scheduler
loop): entry points are read at process start.

Installation over the API is **off by default**; enable it with `ARACHNE_PLUGIN_INSTALL=true`
if admins should be able to install through `POST /api/v1/plugins/install`. The marketplace is
a data file (`ARACHNE_MARKETPLACE` points at your own index), so the workflow works
air-gapped.

### 15.1 Signing: fail-closed packs and a signed index (REQ-ECOS-008, WP-16)

Two artifacts carry trust into a deployment: a **content pack** and the **marketplace index**
that points at packs. Both are signature-verified before anything is loaded, and **both are
fail-closed**: with no key configured, nothing signed is accepted, because "no key" must never
mean "accept anything".

```bash
# The deployment's own key. It signs packs and is the first key of the accepted set.
export ARACHNE_INTEGRITY_KEY="$(arachne integrity generate)"   # or your own ≥16-char key

# During a key rotation, accept the OLD key too — both verify until every artifact is re-signed.
export ARACHNE_CONTENT_KEYS="old-key-1,old-key-2"             # comma- or newline-separated
```

| Variable | Default | Meaning |
|---|---|---|
| `ARACHNE_INTEGRITY_KEY` | *(none)* | The deployment key: signs packs, indexes, audit heads and evidence. |
| `ARACHNE_CONTENT_KEYS` | *(none)* | **Additional** keys accepted for verification only (rotation overlap). Never used to sign. |
| `ARACHNE_PLUGIN_ALLOW_UNSIGNED` | `false` | Accept an unsigned *pack* (a lab). Recorded in the audit trail. |
| `ARACHNE_PLUGIN_ALLOW_UNSIGNED_INDEX` | `false` | Accept an unsigned *index* from a path (a lab). Recorded by the caller. |

**What changed in WP-16, and the migration.** Until WP-16 a marketplace index was read with no
signature check at all, and a pack was refused only when its signature failed to verify. If you
point `ARACHNE_MARKETPLACE` at your own index today, that index is now **refused** until it
carries a signature:

```
REFUSED: /etc/arachne/marketplace/index.yaml carries no signature. A marketplace index
redirects trust — a compromised one points its verified entries anywhere — so an
operator-supplied index must carry a 'signature' field signed with a key in this deployment's
content key set. Sign it, or set ARACHNE_PLUGIN_ALLOW_UNSIGNED_INDEX=true to accept it anyway
(an explicit, documented exception)
```

To migrate, sign the index with a key in your set:

```python
# Signing an index is one call; `sign_index` covers the document without its own signature.
import yaml
from pathlib import Path
from arachne.core.signing import build_content_keyring
from arachne.plugins.marketplace import sign_index

path = Path("/etc/arachne/marketplace/index.yaml")
document = yaml.safe_load(path.read_text())
signer = build_content_keyring().signer  # the primary key: the one that signs
path.write_text(yaml.safe_dump(sign_index(document, signer), sort_keys=False))
# `arachne plugin marketplace` then reports "signature-verified" instead of refusing.
```

Set `ARACHNE_PLUGIN_ALLOW_UNSIGNED_INDEX=true` only as a temporary measure on a lab host: it is
recorded, printed as `UNSIGNED (not verified)` in `arachne plugin marketplace`, and no entry
from such an index can be installed by name (see below). The **bundled** index is exempt — it
ships inside the package, so its integrity is the package's, not a runtime signature's.

**Installing from the catalogue, before anything is downloaded.** `arachne plugin install
--entry <name>` resolves the source from the index and refuses, in this order, an entry that is
not trustworthy: an index that is not signature-verified; an entry not marked reviewed by the
maintainers; an entry claiming review but naming no `pack_key_id`; and a pack whose signing key
is outside your accepted set. Nothing is fetched until all four pass, which is the point — a
compromised index cannot make your host download anything.

```bash
arachne plugin install --entry arachne-example-check-plugin --dry-run   # verify, then print pip
```

**Rotation without a flag day.** Add the new key to `ARACHNE_CONTENT_KEYS` *before* re-signing
anything: both keys verify during the overlap, so packs and indexes signed under either one keep
loading. When every artifact is re-signed, drop the old key. Signing always uses
`ARACHNE_INTEGRITY_KEY`, so a rotation key can verify but never mint.

### 15.2 Writing a check: the SDK (REQ-ECOS-007, WP-16)

The authoring path is one command and no reading:

```bash
arachne plugin new-check m4.header-missing --out ./my-check
cd my-check && python -m pytest tests -q         # green before you edit anything
# implement the claim, record the response that made you write it, then:
arachne plugin conform conformance.yaml
```

`new-check` writes a check, its test, its framework-mapping entry, a positive fixture, a decoy
fixture, a docs stub, the conformance manifest and a `pyproject.toml` that registers it under
`arachne.modules`. The output is ruff- and mypy-clean and its own test passes with **zero
edits** — the repository's suite asserts exactly that, so a scaffold that needs fixing fails the
build rather than the author. `docs/plugin-developer-guide.md` §2 is the worked example, and
`arachne plugin conform` is the gate a reviewer runs: it refuses a check with no framework
mapping, an L2+ declaration without its opt-in, no decoy, or a finding with no
verification-relevant evidence.

### 15.3 Outbound event schemas (REQ-ECOS-009, WP-16)

Every webhook payload — Slack, Teams, Jira, ServiceNow, DefectDojo and the SIEM export — carries
`event` and `schema_version` in its body and the same two values in the `X-Arachne-Event` /
`X-Arachne-Schema-Version` headers. A receiver can therefore recognise a shape it does not
understand instead of failing to parse it. The schemas are published as JSON Schema:

```bash
arachne events catalogue                                  # every event, its version, its fields
arachne events catalogue --write ./schemas                # the JSON Schema documents
arachne events check captured-payload.json                # validate a recorded payload
```

A breaking change to a payload mints a **new event version** rather than changing a shape under
the old one, so a receiver that pinned `finding.jira@1.0` keeps working.

## 16. White-label reports (MSSP)

A branding document changes the cover, colours, logo, classification banner, footer and
contact of every format; a project's `branding` overrides it field by field.

```yaml
# branding.yaml
company_name: Acme Security
product_name: ARACHNE
tagline: Managed detection & response
primary_color: "#1f4e79"
accent_color: "#c00000"
logo_url: https://acme.example/logo.png    # http(s) or data:image only
logo_text: AC                              # used where an image cannot be (Markdown)
footer_text: Prepared for Acme Corp
contact: soc@acme.example
classification: CONFIDENTIAL
show_arachne_branding: false
```

```bash
ARACHNE_REPORT_BRANDING=/etc/arachne/branding.yaml arachne report --scan 7 --format pdf
arachne report --scan 7 --brand ./branding.yaml
arachne project create acme --branding ./branding.yaml    # per-tenant branding
```

The default presentation is unchanged, so an unbranded deployment renders exactly what it
did before S14. The JSON report carries a `branding` block (report schema 1.1).

## 17. Containers

See [`docker/README.md`](../docker/README.md). In short:

```bash
docker compose -f docker/docker-compose.yml up --build           # demo stack (offline scan)
docker compose -f docker/docker-compose.yml -f docker/docker-compose.prod.yml up -d
```

The demo brings up `db`, `migrate`, `scan`, `api` and `worker`. `scan` runs a real heuristic
scan of the bundled target using recorded responses and writes
`demo-report.md`/`demo-report.html` to the `reports` volume. The prod overlay mounts the
database password and the API-key list as Docker secrets.

## 18. Distributed scan execution (multi-node fleet, S16)

By default every scan admitted by the API or the scheduler runs in the process that
admitted it — the documented single-node deployment. Enabling **distributed mode** swaps
ownership for a work queue: producers (the API, the scheduler) *enqueue* admitted scans
on the shared database, and `arachne agent` workers lease and execute them. The database
is the broker — the queue is a Postgres table claimed with
`SELECT … FOR UPDATE SKIP LOCKED`, and no message broker is ever a dependency
(REQ-SCALE-001). Postgres is required for distributed mode (any Postgres 12+; set
`ARACHNE_DATABASE_URL`), while single-node deployments keep working on SQLite unchanged.

### 18.1 Enable it

```bash
# the coordinator (API): producers enqueue instead of running scans
ARACHNE_DATABASE_URL=postgresql+psycopg://arachne@db/arachne \
ARACHNE_DISTRIBUTED=true \
ARACHNE_API_KEYS="admin:admin:$(cat /run/secrets/k);fleet:scanner:$(cat /run/secrets/agent-k)" \
arachne db upgrade && arachne serve

# a worker (one process per node; run N for N-way parallelism)
ARACHNE_DATABASE_URL=postgresql+psycopg://arachne@db/arachne \
ARACHNE_AGENT_NAME=fleet-1 \
ARACHNE_API_URL=https://arachne.internal \
ARACHNE_API_KEY="$(cat /run/secrets/agent-k)" \
arachne agent
```

`arachne agent` (a **scanner-role** API key — the agent is a scanner, not a new
credential type) registers with the deployment, leases queued scans one at a time,
executes them through the real orchestrator, heartbeats the lease while a scan runs and
acks completion. Without `--api-url` the worker runs against its local store directly
(`ARACHNE_DISTRIBUTED=true` still required so producers enqueue). `arachne agent --once`
drains the queue and exits (cron/systemd friendly); `--concurrency N` raises the
per-agent cap for small, fast targets.

| Variable | Default | Meaning |
|---|---|---|
| `ARACHNE_DISTRIBUTED` | `false` | Producers enqueue instead of running scans in-process. |
| `ARACHNE_AGENT_NAME` | *(unset; `agent-<host>`)* | The agent's fleet name (the audit trail carries it). |
| `ARACHNE_AGENT_CONCURRENCY` | `1` | Per-agent cap: scans one agent runs at the same time. |
| `ARACHNE_LEASE_TTL_S` | `300` | A lease not heartbeated for this long is reclaimed. |
| `ARACHNE_AGENT_HEARTBEAT_S` | `15` | Heartbeat/lease-renewal interval while a scan runs. |
| `ARACHNE_AGENT_POLL_S` | `1` | Idle poll interval. |
| `ARACHNE_API_URL` | *(unset)* | The deployment's base URL for a remote agent. |
| `ARACHNE_API_KEY` | *(unset)* | API key for `--api-url` (scanner role). |

### 18.2 What the fleet guarantees

* **No scan runs twice.** `scan_queue` grants exactly one lease per scan
  (`scan_id` is unique; claims are atomic), so concurrent agents never receive the same
  scan (REQ-SCALE-001/002).
* **A dead agent loses nothing.** If an agent is killed mid-scan, its lease expires
  (`ARACHNE_LEASE_TTL_S`), the next claimant re-queues the scan with an interruption
  note (visible in the scan's `stats.interruptions` and as `scan.interrupted` in the
  audit trail), and another agent resumes it from the persisted lifecycle state —
  completed steps are never re-run (REQ-SCALE-003).
* **Gates are evaluated where the scan runs.** The executing node re-checks the scope
  gate (its own `ARACHNE_SCOPE_*` allowlist and the project's scope), the authorization
  gate (the attestation as it stands at execution time — revoking an attestation stops
  an already-enqueued scan) and the proof gate before any request is sent
  (REQ-SCALE-008). Distribution never weakens a gate.
* **Plans are identical everywhere.** The plan is computed once at admission and stored
  with the scan; agents execute the stored plan, so the same scan id means the same plan
  on every node (REQ-SCALE-006).
* **Results stream.** Findings, evidence and assets are committed to the central store
  as the producing check finishes — a second reader sees them while the scan is still
  running (REQ-SCALE-005).
* **The scheduler is a producer.** With distributed mode on, a due schedule admits and
  enqueues its scan; the change-detection diff is computed when an agent completes the
  scan (REQ-SCALE-007).

### 18.3 Operating the fleet

```bash
curl -s -H "x-api-key: $VIEWER" https://arachne.internal/api/v1/agent/queue
# -> {"stats": {"done": 41, "leased": 2, "queued": 7}, "agents": [...]}
```

`GET /api/v1/agent/queue` shows the queue depth and every registered agent (name, node,
concurrency cap, last heartbeat). Agents authenticate every control-plane call
(`POST /api/v1/agent/register|heartbeat|lease|complete`) with their scanner key, and
every audit line an execution writes is signed `agent:<name>` — "which node ran this?"
is answerable from the trail alone. `POST /api/v1/scans/{id}/stop` cancels a queued or
leased scan fleet-wide: the row is cancelled and the holding agent aborts on its next
heartbeat. Stopping an agent process (Ctrl-C) leaves its leases to expire; the scans
re-queue and another agent picks them up.

## 19. Enterprise identity & access (S17, area IDAM)

Three credential types authenticate the API and the web UI, all resolved by one store:
**static API keys** (`ARACHNE_API_KEYS`, unchanged), **service accounts** (DB-backed keys
with rotation/expiry) and **single sign-on** (OIDC authorization-code login). If none is
configured the interface refuses every request — enabling SSO never opens the API, and
disabling it never locks out a deployment that uses keys.

### 19.1 Single sign-on (OIDC)

| Variable | Default | Meaning |
|---|---|---|
| `ARACHNE_SSO_ENABLED` | `false` | Opt-in switch. SSO exists only when this is true **and** issuer/client id are set. |
| `ARACHNE_SSO_ISSUER` | *(unset)* | Provider issuer URL; the ID token's `iss` must equal it. |
| `ARACHNE_SSO_CLIENT_ID` | *(unset)* | OAuth client id (also the required `aud`). |
| `ARACHNE_SSO_CLIENT_SECRET` | *(unset)* | Client secret (env-only; never logged). |
| `ARACHNE_SSO_REDIRECT_URL` | *(derived)* | Callback URL; defaults to `{api.base_url}/api/v1/auth/sso/callback`. |
| `ARACHNE_SSO_SCOPES` | `openid,profile,email` | Requested scopes (`openid` is required). |
| `ARACHNE_SSO_ROLE_CLAIM` | `groups` | The claim carrying group membership. |
| `ARACHNE_SSO_GROUP_ROLES` | *(empty)* | `group:role` bindings, comma-separated, e.g. `arachne-admins:admin,arachne-scanners:scanner`. |
| `ARACHNE_SSO_DEFAULT_ROLE` | *(unset)* | Role for a login matching no group. Unset means **deny** a login that maps to nothing. |
| `ARACHNE_SSO_ALGORITHMS` | `RS256,HS256` | Accepted ID-token algorithms (never `none`; `RS256` recommended). |
| `ARACHNE_SSO_AUTHORIZATION_ENDPOINT` / `_TOKEN_ENDPOINT` / `_JWKS_URL` | *(discovered)* | Explicit endpoints; omitted, they come from `{issuer}/.well-known/openid-configuration`. |
| `ARACHNE_SSO_ALLOWED_HOSTS` | *(empty)* | Extra hosts the IdP calls may reach (an internal alias next to the issuer host). |
| `ARACHNE_SSO_SESSION_MAX_AGE` | `28800` | SSO session cookie lifetime, seconds. |
| `ARACHNE_SSO_FLOW_TTL` | `600` | How long a started login may take to complete. |
| `ARACHNE_SSO_LEEWAY` | `60` | Clock-skew allowance on `exp`/`nbf`. |

Register `https://your-arachne/api/v1/auth/sso/callback` as the redirect URI at the
provider, and grant the browser session cookie an `HttpOnly`, `SameSite=Strict` secure
cookie (the default when TLS is configured).

```bash
# Example: an IdP whose group "secops" is admin and "appsec" is scanner.
export ARACHNE_SSO_ENABLED=true
export ARACHNE_SSO_ISSUER=https://login.example.com/realms/corp
export ARACHNE_SSO_CLIENT_ID=arachne
export ARACHNE_SSO_CLIENT_SECRET="$(cat /run/secrets/oidc-client-secret)"
export ARACHNE_SSO_GROUP_ROLES="secops:admin,appsec:scanner,all-staff:viewer"
export ARACHNE_SSO_REDIRECT_URL=https://arachne.internal/api/v1/auth/sso/callback
arachne serve --host 0.0.0.0 --port 8443 --cert /etc/arachne/tls.crt --key /etc/arachne/tls.key
```

The web UI login page then shows **Sign in with SSO**. The role is derived from the
groups on every login (the highest-ranked matching group wins), so removing a group at
the IdP takes effect at the user's next login. A login that maps to no role is refused
and audited; see §19.4.

### 19.2 Service accounts (rotatable API keys)

When an integration needs a key that can expire and be rotated without editing the
environment, create it through the API as an admin:

```bash
ADMIN=...   # an admin key or an SSO session cookie

# Create — the secret is returned once; store it in your secret manager.
curl -s -X POST https://arachne.internal/api/v1/service-accounts \
  -H "x-api-key: $ADMIN" -H 'Content-Type: application/json' \
  -d '{"label":"ci-pipeline","role":"scanner","owner":"alice@corp","expires_in_s":7776000}'
# -> {"account": {...}, "secret": "…"}     # 90 days, owned by alice@corp

# List (never shows a secret; last_used_at answers "is it still in use?").
curl -s https://arachne.internal/api/v1/service-accounts -H "x-api-key: $ADMIN"

# Rotate — the old secret stops working immediately; the new one is returned once.
curl -s -X POST https://arachne.internal/api/v1/service-accounts/ci-pipeline/rotate \
  -H "x-api-key: $ADMIN"

# Revoke — the key never authenticates again; the row is kept for audit lineage.
curl -s -X POST https://arachne.internal/api/v1/service-accounts/ci-pipeline/revoke \
  -H "x-api-key: $ADMIN"
```

Storage is unchanged from S12: only a SHA-256 digest of the secret is stored and
verification uses `hmac.compare_digest`. All three change verbs are audited as
`service_account.changed` (created / rotated / revoked). Omit `expires_in_s` for a
non-expiring key; set `owner` (or create it while signed in with SSO, which defaults the
owner to you) so the audit trail reads "user X via key Y".

### 19.3 Identity in the audit trail

Every action an identity triggers records the actor as:

| Caller | Actor |
|---|---|
| SSO session | `user alice@corp` |
| Service account with an owner | `user alice@corp via key ci-pipeline` |
| Static key / ownerless account | `key ci-pipeline` |
| Missing/invalid credential | `anonymous` (a refusal) |

`GET /api/v1/auth/me` returns the same `actor` (with `role`, `source` and groups), so a
client can confirm how it will be attributed. The requester is also stored on the scan
(`stats.requested_by`) and rendered in report §2 as "Requested by".

### 19.4 Deny-by-default and refusals

* With no IdP configured, `GET /api/v1/auth/sso/login` and the callback answer `503` and
  the API still requires a key or service account (`401`).
* A valid login whose groups map to none of `ARACHNE_SSO_GROUP_ROLES` (and no
  `ARACHNE_SSO_DEFAULT_ROLE`) is refused; the callback redirects to the login page and
  writes an `api.denied` audit line with the user and group list.
* A replayed/expired `state`, a nonce mismatch, a wrong issuer/audience or an expired ID
  token are all refusals — each audited, none yielding a session.
* **SCIM 2.0 provisioning ships** at `/api/v1/scim/v2` (RFC 7643/7644), authenticated **only**
  by a dedicated provisioner credential — a service account holding the provisioner role. A
  viewer key and a static admin key are both refused, so "which provisioner changed this?" is
  always answerable. `DELETE /Users/{id}` deactivates the principal and revokes its live
  sessions *and* the service-account keys it owns in one request.
* **LDAP is deliberately not implemented** (REQ-IDAM-008, P2, deferred): there is no
  `LdapSettings`, no bind path and no route, so nothing claims it works. See
  `docs/scim-ldap-interface.md` for the shipped SCIM contract and the LDAP design a future
  release would implement.

### 19.5 Troubleshooting SSO

| Symptom | Likely cause |
|---|---|
| `503 single sign-on is not configured` | `ARACHNE_SSO_ENABLED` false, or issuer/client id unset. |
| Redirect loop / `invalid session` | The provider did not return to the exact `ARACHNE_SSO_REDIRECT_URL`. |
| Login succeeds, then `403` | The user's groups match no `group_roles` entry (deny by default). |
| `401` after login | Session expired (`ARACHNE_SSO_SESSION_MAX_AGE`) or was revoked by logout. |
| Token exchange fails | Clock skew (> `ARACHNE_SSO_LEEWAY`), or an internal IdP blocked by the URL policy — set `ARACHNE_ALLOW_PRIVATE_IPS` if the IdP is on a private address, and `ARACHNE_SSO_ALLOWED_HOSTS` for an alias. |

## 20. Live threat intel & passive OSINT (S18, area INTEL)

Two capabilities, one section, because they answer the same question from opposite sides:
*how current is what we know?* §14 brings a file in by hand; §20 fetches the feeds itself and
lets the scanner ask third-party indexes about **your** address space.

Both are **off by default** and both are allowlisted the same way the target scope is: a host
that is not named in the configuration is not reachable, and the refusal is audited.

### 20.1 Feed sync (NVD API 2.0, CISA KEV, FIRST EPSS)

```bash
# one-off: fetch, verify and import all three sources
ARACHNE_INTEL_ENABLED=true arachne intel sync

# a single source, and a JSON view for a pipeline
arachne intel sync --source kev --json

# what the deployment is actually scanning against (also what the report renders)
arachne intel status

# regenerate the CVE-index baseline from the synced NVD corpus
arachne intel build-index --output /etc/arachne/cve-index-baseline.yaml
```

Configuration (`core/config.py`, `IntelSettings`):

| Variable | Default | Meaning |
|---|---|---|
| `ARACHNE_INTEL_ENABLED` | `false` | Master switch. Off = no sync service is built at all. |
| `ARACHNE_INTEL_FEED_SOURCES` | `nvd,kev,epss` | Sources `sync` fetches when none is named. |
| `ARACHNE_INTEL_FEED_VERIFY` | `checksum` | `checksum` (SHA-256 pins) or `signature` (detached RSA). |
| `ARACHNE_INTEL_FEED_CHECKSUMS` | — | Inline pins: `nvd=sha256:…,kev=sha256:…` |
| `ARACHNE_INTEL_FEED_CHECKSUMS_FILE` | — | A manifest instead (`{"kev": "sha256:…"}` or `name=digest` lines). |
| `ARACHNE_INTEL_FEED_PUBLIC_KEY` | — | PEM public key for `verify=signature`. |
| `ARACHNE_INTEL_FIXTURES` | — | Replay recorded responses instead of fetching (offline demos, tests). |
| `ARACHNE_INTEL_MAX_BYTES` | 64 MiB | Response cap; a truncated body is refused, never verified. |
| `ARACHNE_INTEL_MAX_PAGES` | 20 | Pagination cap for NVD/EPSS windows. |
| `ARACHNE_INTEL_REQUEST_DELAY_S` | 6 | Politeness delay between requests (NVD asks for ≤1 per 6 s unkeyed). |
| `ARACHNE_NVD_API_KEY` | — | NVD API key (raises the rate limit to ~1 request per 0.6 s). |
| `ARACHNE_INTEL_FRESHNESS_TTL` | see below | Hours per kind after which a feed is *stale*: `nvd=168,kev=168,epss=48`. |

**Verification is not optional.** There is no "off" mode (REQ-INTEL-002): a payload is
imported only when it verifies, and a source with no pin is refused rather than trusted.

* *Checksum mode* (default) compares the payload's SHA-256 with the digest you pinned. For a
  single-request source the digest is exactly what `sha256sum` prints for the file you
  fetched; a paginated window is pinned as the concatenation of its pages, so re-pin when a
  window outgrows one page.
* *Signature mode* verifies a detached RSASSA-PKCS1-v1_5 (SHA-256) signature against a pinned
  RSA public key. Use it when you mirror the feeds and sign them, or when your upstream
  publishes signatures. The key is the trust anchor; the digest is provenance.
* `--pin` is the one explicit trust-on-first-use act: it fetches, records the digests in the
  manifest, and then runs the normal verify-and-import pass **against the manifest it just
  wrote** (`intel.checksums_pinned` is audited). Every later sync is fail-closed.

A rejected feed writes nothing — no rows, no artefact — and is audited as
`intel.feed_rejected` with the expected and observed digests. An *unchanged* upstream version
is reported as `unchanged` (KEV's `catalogVersion` is the usual case), not as a new import.

Sync is **incremental and versioned**: NVD resumes from the `lastModEndDate` it reported
(minus a one-day overlap), EPSS asks for scores changed since the last score date, and each
feed row stores the upstream version plus a cursor for the next run.

### 20.2 Where the data lands, and what reads it

`arachne intel sync` imports through the same store as `arachne feeds import` (§14), so the
normalised artefact it writes is exactly what the checks already read:

* `epss` / `kev` — consumed by M6's correlation (`ARACHNE_M6_EPSS_FEED` / `_KEV_FEED`).
* `nvd` — the richer corpus (CVSS, CWE, CPE ranges) the index generator reads.
* `feeds` / `feed_entries` rows — `arachne feeds list|show|lookup`, the web UI and the API.

`arachne intel build-index` turns the `nvd` corpus into a **generated baseline**
(`templates/m2/cve-index-baseline.yaml`, header marked `GENERATED FILE`). The M2 CVE index a
scan reads is that baseline merged with the **curated overlay**
(`templates/m2/cve-index.yaml`, §14's file), and the overlay wins on a repeated
`(product, cve)` pair. Point the loader at your own generated file with
`ARACHNE_CVE_INDEX_BASELINE`, or set it to `off` to use the overlay alone. The product map the
generator filters on is `templates/m2/cve-index-products.yaml` (`ARACHNE_CVE_INDEX_PRODUCTS`).

### 20.3 Freshness in the report

Every admitted scan records a snapshot (`scans.stats["intel"]`: per kind the active artefact,
its upstream version, import time, age, TTL, staleness and **whether it verified**). Report
appendix **§G "Threat-intel freshness"** renders it, and the JSON report carries it as a
top-level `intel` block (schema **1.4**).

Three states are distinguished on purpose:

* **fresh** — ingested and inside its TTL;
* **stale** — ingested, older than its TTL (the report says so at the top of the section);
* **not ingested** — no artefact of that kind: a match against data nobody loaded is not a
  clean result, so the absence is stated rather than implied.

### 20.4 Passive OSINT providers (Shodan, Censys, WHOIS/RDAP, CT logs, HIBP)

Five providers, all behind the pattern §14's passive checks already use: each has one fixed
host in the deployment allowlist, a declared credential, a pacing rate, and an `opt_in` flag
that keeps it out of the default provider list.

| Provider | Host | Credential | Used by |
|---|---|---|---|
| `shodan` | `api.shodan.io` | `ARACHNE_SHODAN_API_KEY` | `m1.service-exposure-drift` |
| `censys` | `search.censys.io` | `ARACHNE_CENSYS_API_ID` + `ARACHNE_CENSYS_API_SECRET` | `m1.service-exposure-drift` |
| `certspotter` | `api.certspotter.com` | none | `m1.ct-surprise` |
| `whois` (RDAP) | `ARACHNE_OSINT_WHOIS_URL` (default `https://rdap.org/domain/{query}`) | none | `m1.ct-surprise` |
| `hibp` | `haveibeenpwned.com` | `ARACHNE_HIBP_API_KEY` | `m1.breach-exposure` |

Turn one on with **two** explicit declarations — the provider, and the check:

```bash
export ARACHNE_OSINT_ENABLED=true
export ARACHNE_OSINT_PROVIDERS="crtsh,circl,internetdb,shodan,censys,certspotter,whois,hibp"
export ARACHNE_SHODAN_API_KEY="…"
export ARACHNE_HIBP_API_KEY="…"

arachne scan --target target.yaml --check m1.service-exposure-drift,m1.ct-surprise,m1.breach-exposure
arachne intel status          # shows which providers are enabled and which are opted in
```

Three rules hold structurally, not by convention:

1. **No opt-in, no call.** Enabling OSINT with the defaults does not reach any of the five.
   A provider named without its credential is dropped from the scope *and* disabled before any
   check runs, so "half configured" produces a skip with the reason — and an
   `intel.provider_blocked` audit line — never an unauthenticated request.
2. **Keys never reach a record.** Credentials are read from the environment into `SecretStr`
   and used only to build a header (Censys basic auth, HIBP's `hibp-api-key`) or a query
   parameter (Shodan's API has no header form). Everything that records a URL — the audit
   trail, the log line, the provider response and the finding's evidence — stores
   `redact_url(...)`, so `?key=…` appears as `?key=[REDACTED:query-param]`.
   `tests/test_safety.py::test_a_provider_key_never_reaches_a_log_line_a_record_or_a_finding`
   is the log-scan that keeps it true.
3. **Missing keys degrade, never fail.** Each check reports "not run" with the variable it
   needs; the rest of the scan is unaffected.

Per-provider pacing is applied by the provider layer on top of the shared client's per-host
limiter (`ARACHNE_OSINT_PROVIDER_RATE_LIMITS="shodan=0.5,hibp=0.2"`, requests/second). The
defaults are deliberately conservative: these are somebody else's tiers, and the key is not
yours alone.

`m1.ct-surprise` counts a certificate as recent within `ARACHNE_OSINT_CT_WINDOW_DAYS`
(default 14). RDAP referrals to an authoritative server are *not* followed unless that host is
in `ARACHNE_OSINT_EXTRA_HOSTS` (or the provider is pointed at your own RDAP mirror): a
referral to an unknown host is refused by the scope, which is the same rule as everywhere
else, and the check reports the names it could read.

### 20.5 Air-gapped and offline operation

* Feed sync: set `ARACHNE_INTEL_FIXTURES` to a directory of recordings
  (`{"source": "kev", "body": "<the document>"}` per file, plus an optional `<source>.sig`) and
  `sync` runs the whole path — parse, verify, import, audit — with no packet leaving the
  process. The shipped recordings live in `tests/fixtures/intel/` and carry their own pins.
* Providers: `ARACHNE_OSINT_FIXTURES` replays recorded responses for the M1 checks (unchanged
  from §14), so an opted-in provider can be demonstrated with no network at all.

### 20.6 Troubleshooting

| Symptom | Likely cause |
|---|---|
| `intel sync` exits 1 with `rejected` | The payload did not match its pin (or no pin exists for that source). Re-pin deliberately with `--pin` only after confirming the mirror is yours. |
| `refusing to import an unverified feed` | No digest for the source: add `ARACHNE_INTEL_FEED_CHECKSUMS` or a manifest, or run `--pin` once. |
| `intel verify` says REJECTED | Expected for a changed file; compare the printed digest with the publisher's. |
| A feed shows **not ingested** in the report | `sync` never imported it (rejected, or never run). `intel.feed_rejected` in the audit trail says why. |
| `provider 'shodan' needs shodan_api_key` | The provider is selected but the credential is not in the environment. |
| A provider check reports "strictly opt-in" | The provider is not in `ARACHNE_OSINT_PROVIDERS` — naming it is the opt-in. |
| RDAP names look incomplete | The referral host is outside the allowlist; add it to `ARACHNE_OSINT_EXTRA_HOSTS` or point `ARACHNE_OSINT_WHOIS_URL` at your mirror. |

## 21. Authenticated scans: the credential vault (S19, area CREDS)

An anonymous scan measures what a stranger sees. Most of an enterprise application is behind a
login, so the highest-value answers — *what does a signed-in user reach? does logout actually end
the session?* — need a credential. S19 adds one, without letting it leak and without letting it
wander: a credential belongs to a **node** and to a **scope**, and a check never touches it.

### 21.1 Create the vault

The vault is one encrypted file on the scanning node (scrypt + SHAKE-256 keystream + HMAC-SHA256,
the S7 sidecar construction) under its own magic. There is no database table and no API: the file
*is* the boundary (ADR-240.2).

```bash
# The passphrase comes from the environment (or a hidden prompt) — never from argv.
export ARACHNE_VAULT_PATH=/etc/arachne/credentials.enc
export ARACHNE_VAULT_KEY='a long passphrase you keep in your secret manager'

# A web login: scope it to the host it may be spent on.
export ARACHNE_VAULT_SECRET='the account password'
arachne vault put portal \
  --kind web-form --username carol --scope-host app.internal \
  --login-json '{"url":"https://app.internal/login","format":"form",
                 "username_field":"username","password_field":"password",
                 "protected_url":"https://app.internal/account",
                 "logout_url":"https://app.internal/logout"}'

# A protocol credential (an SMB account; --extra carries the domain).
ARACHNE_VAULT_SECRET='svc password' arachne vault put hosts \
  --kind smb --username svc-backup --scope-host 10.20.0.15 --extra DOMAIN=CORP

arachne vault list          # labels, kinds and scopes — never material
arachne vault show portal   # one entry's metadata; there is no verb that prints a secret
arachne vault revoke portal # keep the entry as a visible refusal
```

Configuration (`core/config.py`, `VaultSettings`):

| Variable | Default | Meaning |
|---|---|---|
| `ARACHNE_VAULT_PATH` | — | The encrypted vault file. Unset = no vault, so credentialed checks report themselves skipped. |
| `ARACHNE_VAULT_KEY` | — | The passphrase. **Required** when a path is set: the vault refuses to read or write without it. |
| `ARACHNE_VAULT_MAX_ENTRIES` | `256` | Cap on stored entries. |
| `ARACHNE_VAULT_SECRET` | — | Where `vault put` reads the secret (or pass `--secret-env VAR`). |

A credential's **scope** is the hosts and/or URL prefixes it may be used against. An unscoped
credential covers nothing, and a credential offered for a target outside its scope is refused
*before* a request is made (`credential.scope_rejected`).

### 21.2 Run an authenticated scan

Name the credential **label** on the scan — the label travels, the material does not:

```bash
arachne scan target.yaml --credential portal
# target.yaml: options: {active_checks: true, credentials: [portal],
#                        modules: {checks: [m3.authenticated-surface, m3.session-logout]}}
```

What happens, in order:

1. the checks step crawls the surface **anonymously** (that is the baseline);
2. the broker logs in through the same scoped HTTP client — its cookie jar now holds the
   session, and the session token never enters ARACHNE's own code;
3. the surface is crawled again, authenticated; the difference is the authenticated area;
4. `m3.authenticated-surface` reports what a session adds (and flags administrative or account
   paths among it); `m3.session-logout` logs out and re-probes, reporting a session that survives
   its own logout (CWE-613).

Both checks are **opt-in** (`enabled_by_default=false`) and need the active-checks opt-in plus an
attestation — a credential authenticates a scan, it does not authorize it.

Session keep-alive: if the session expires mid-scan, the broker re-establishes it (bounded) and
records `auth.session_expired`; if it cannot, the scan's report says the authenticated checks
degraded to anonymous instead of silently pretending otherwise.

Credentialed host checks: `m2.smb-auth` (opt-in, active) authenticates one vault SMB credential
over an SMB2 NTLMSSP exchange and reports the peer's own NTSTATUS — accepted or refused. It
never guesses, sprays or reuses a credential (ADR-240.4).

The report records `scope.credentials` (labels) and `scope.authenticated`, so a reader knows the
report describes an authenticated surface, and with which vault entry.

### 21.3 Troubleshooting

| Symptom | Likely cause |
|---|---|
| `no vault is configured` | `ARACHNE_VAULT_PATH`/`ARACHNE_VAULT_KEY` are not in this process's environment. |
| `could not be authenticated` | Wrong `ARACHNE_VAULT_KEY`, or the file was modified. Both look identical on purpose. |
| `credential 'x' is scoped to … and does not cover …` | The vault entry's scope does not include this target. Fix the scope, do not widen the scan. |
| `credential.unresolved` in the audit trail | This node does not hold that label (internal agent, ADR-240.8): the scan runs unauthenticated rather than borrowing one. |
| The credentialed checks report "not run" | No credential was named, no credential covered the origin, or the login was refused — the skip note says which. |
| Login accepted but the surface is empty | The application redirected to the login page after the POST: pass a `protected_url` in `--login-json` so the check can verify the session. |
| `m3.session-logout` says "not run" | No logout endpoint is known: declare `logout_url` in `--login-json` (the check will not guess a path). |

## 22. Internal agent mode (S19, REQ-CREDS-003)

An agent can be deployed **inside** the target network — the placement an assessment of a
segmented environment usually needs. It pulls jobs and pushes findings exactly as §18 describes;
what changes is where a credential may come from.

```bash
# On the internal node: its own vault, its own scope, its own identity.
export ARACHNE_AGENT_MODE=internal
export ARACHNE_ALLOW_PRIVATE_IPS=true
export ARACHNE_VAULT_PATH=/etc/arachne/internal-credentials.enc
export ARACHNE_VAULT_KEY='…'
arachne agent --name internal-dmz --api-url https://arachne.central:8443
```

The guarantees:

* **Labels travel, material does not.** The scan request (queue row, `request_json`, HTTP control
  plane) carries `credentials: ["portal"]`. No credential value is ever on the wire.
* **Resolution happens after the lease, on this node.** If this node does not hold the label, the
  scan runs unauthenticated and the refusal is audited (`credential.unresolved`) — an internal
  node never reaches for a credential it was not given.
* **No gate is relaxed.** The scope gate (this node's `ARACHNE_ALLOW_*` posture and the scan's
  project scope), the attestation gate and the proof gate are re-run on the executing node by the
  same code path as an external agent's.
* **The mode is on the trail.** `agent.mode` records `mode=internal`, `vault=local` and the node's
  private-network posture, so "was this scan run from inside?" is answerable afterwards.

A node without a vault still runs scans; they are simply anonymous. Configure the vault on the
nodes that are meant to authenticate, and treat the vault file like any other secret: `0600`,
root-owned, backed up only in encrypted form.

## 23. Data lifecycle, evidence storage & observability (S20, areas DATA/OPS)

Three problems that no detection improvement solves: the data grows without bound, it grows in
the *database*, and nobody can see what the fleet is doing. This section is the operator's view
of the answer; the reasoning is in
[`adr/250-stage-20-data-lifecycle.md`](adr/250-stage-20-data-lifecycle.md).

### 23.1 Retention: what may I keep, and for how long?

A retention policy has four day counts plus an on/off switch, and it is resolved **per
project** (`projects.retention_json`) over the deployment defaults (`ARACHNE_RETENTION_*`):

```
arachne retention status                     # every tenant: policy, storage used, quota
arachne retention policy --project acme --findings-days 30 --evidence-days 7 --audit-days 0
arachne retention policy --project acme --hold    # legal hold: plan and delete nothing
arachne retention policy --project acme --clear   # back to the deployment defaults
```

Two values matter more than the rest:

* **`0` days keeps that category for ever.** A tenant with a seven-year audit obligation sets
  `--audit-days 0` and turns off audit retention *for them*, without turning it off for
  everyone else.
* **`--hold` is a legal hold** (`enabled: false`): the job plans nothing and deletes nothing
  for that project, and `retention status` renders it as `(legal hold)` so nobody has to guess
  why the data is still there.

**Audit is deployment-wide.** `audit_log` rows carry an actor and an action, not a tenant, and
one audit line can name several. The audit cutoff is therefore the *smallest* non-zero
`audit_days` among all configured policies — the shortest obligation wins, which is the only
rule that cannot retain one tenant's records longer than that tenant allows.

### 23.2 The pruning job: dry run first, always

```
arachne retention plan                 # what a run WOULD delete (read-only)
arachne retention plan --json          # the same, machine-readable
arachne retention prune                # the same plan; deletes nothing
arachne retention prune --apply        # the plan, carried out
```

`prune` without `--apply` is a dry run; that is the default, not a flag on a dangerous default.
A plan selects concrete row ids and the apply step deletes exactly those ids, so "dry run, then
apply" cannot drift even though the clock keeps moving between the two. Both paths write an
audit line (`retention.planned` / `retention.pruned`) with the per-category counts, per project.

What a run removes and what it reports:

| Category | Removed when | Reported as |
|---|---|---|
| `scans` | `scans.created_at` is older than the project's `scans_days` | `rows`, plus `cascaded_rows` for the findings and evidence the scan took with it |
| `findings` | older than `findings_days`, scan survives | `rows` (+ the evidence those findings took with them, in `bytes`) |
| `evidence` | older than `evidence_days`, finding survives | `rows` and `bytes` |
| `audit` | older than the strictest `audit_days` | `rows` |

**Feeds are never pruned.** A feed is *superseded*, not stale: its artefacts are versioned
reference data that the CVE index and past reports cite. Use `arachne feeds` to manage them.
**The credential vault is never pruned** either — it is operator data, not scan data.

The job is bounded by `ARACHNE_RETENTION_BATCH_LIMIT` (10 000 rows per category per run), so a
first prune on a years-old database is a series of repeatable runs rather than one enormous
transaction. Evidence objects are unlinked *after* the rows commit: a failure to unlink leaves
an orphan (visible in the backend stats) rather than a row pointing at nothing.

### 23.3 Where evidence lives (and why it may not be in the database)

Evidence stays inline in `evidences` below `ARACHNE_EVIDENCE_OFFLOAD_THRESHOLD_BYTES`
(16 KiB default). Above it the payload goes to the **backend** and the row keeps a *stub*: the
scalar fields, every string truncated to `ARACHNE_EVIDENCE_PREVIEW_CHARS` (2 KiB), plus the
object's backend, key, sha256 and size. Reports and the UI render the stub, so an offloaded
finding still reads correctly; the full object has its own route
(`GET /api/v1/evidence/{id}/download`).

```
ARACHNE_EVIDENCE_BACKEND=local                  # default: a directory beside the database
ARACHNE_EVIDENCE_DIR=/var/lib/arachne/evidence
```

* Objects are **content-addressed**: the file name *is* the SHA-256 of the payload, so writing
  the same response body a hundred times costs one object. That is the deduplication mechanism
  (REQ-DATA-004) — there is no separate index to drift.
* Objects are **zlib-compressed** and framed (`MAGIC | flag | size | body`), so every stored
  object is self-describing and verifiable: a corrupted object is refused on read, never served.
* Writes are atomic (temp file + rename), and the local backend streams: each chunk is hashed
  and compressed as it arrives.
* **A payload whose stub would be larger than itself is not offloaded.** The reference metadata
  costs ~230 bytes, so a 100-byte payload would grow the database to shrink nothing. That is why
  a threshold below ~512 bytes has no effect: the rule is "offload when it saves space".

For an object store:

```
ARACHNE_EVIDENCE_BACKEND=s3
ARACHNE_EVIDENCE_S3_ENDPOINT=https://s3.example.com
ARACHNE_EVIDENCE_S3_BUCKET=arachne-evidence
ARACHNE_EVIDENCE_S3_REGION=us-east-1
ARACHNE_EVIDENCE_S3_ACCESS_KEY=...
ARACHNE_EVIDENCE_S3_SECRET_KEY=...
```

* Signing is SigV4 with **static credentials only** (no instance roles): all of endpoint,
  bucket, access key and secret are required, and a half-configured backend is a *configuration
  error*, never a silent fallback to the local filesystem.
* Uploads are signed and streamed; a container above `multipart_threshold` (8 MiB) is uploaded
  in parts. Dedup is a signed `HEAD` on the content key before any bytes are sent.
* The object store is reached through the same scoped, rate-limited, audited HTTP client as
  everything else, pinned to the configured endpoint's host. A MinIO on a private address needs
  `ARACHNE_EVIDENCE_S3_ALLOW_PRIVATE_IPS=true`.
* `GET /api/v1/evidence/{id}/download` answers **302 to a presigned URL** (default), so the
  browser fetches straight from the store; `?redirect=false` streams through the API instead.
  Presigned URLs are redacted wherever ARACHNE logs or audits one — they are bearer credentials
  until they expire.

**Moving between backends.** Objects are byte-identical in both, so a migration is
`copy + flip ARACHNE_EVIDENCE_BACKEND + verify`: the row's `sha256` is the digest of the object
in either store, and the backend verifies it on read.

### 23.4 Quotas: warn, then stop, resumably

```
arachne retention quota --project acme --bytes 53687091200    # 50 GiB
arachne retention quota --project acme --clear                # remove the limit
```

`ARACHNE_EVIDENCE_DEFAULT_QUOTA_BYTES` is the quota a project inherits when it declares none.
Above `ARACHNE_EVIDENCE_QUOTA_WARN_RATIO` (80%) the deployment writes one `quota.warning` per
scan; at the limit the write is refused **before it happens**:

```
project 3 has exceeded its storage quota (scan 12): 1050 bytes stored, 900 more requested,
limit 1000 bytes. Nothing was written. Raise the quota (arachne retention quota --project
<slug> --bytes <n>) and resume the scan with `arachne scan --resume <id>`.
```

Nothing is stored, the refusal is audited (`quota.exceeded`, with the check and asset), the
step and the scan are marked `failed` — and that state is **resumable**: raise the quota, run
`arachne scan --resume <id>`, and the scan continues from the failed step rather than starting
over. A quota stop costs the failed step, not the scan.

The quota counts **logical** bytes (what the tenant accumulated), not physical bytes after
compression and dedup: a tenant whose payloads happen to compress well has not used less. The
two are visible separately (`arachne_storage_used_bytes` and the backend's `stored_bytes`).

### 23.5 Metrics: `GET /metrics` (REQ-OPS-003)

```yaml
# prometheus.yml
scrape_configs:
  - job_name: arachne
    static_configs:
      - targets: ["arachne-1:8080", "arachne-2:8080"]   # every worker
```

`ARACHNE_METRICS_ENABLED=false` removes the route; `ARACHNE_METRICS_TOKEN` requires a bearer
token (`Authorization: Bearer …`). The endpoint is aggregate only — no target, asset, finding
title or payload ever reaches a label — because it is scrapeable without an API key.

What you get, and how to read it:

| Metric | Type | Meaning |
|---|---|---|
| `arachne_scans_total{status}` | counter | scans **this process** finished, by status |
| `arachne_scans{status}` | gauge | scans the **deployment** holds, by status |
| `arachne_scan_duration_seconds` | histogram | wall-clock duration of a completed scan |
| `arachne_scan_steps_total{step,status}` | counter | pipeline steps executed |
| `arachne_queue_depth{status}` / `arachne_queue_leases` | gauge | work queue state and live leases |
| `arachne_queue_oldest_age_seconds` | gauge | how long the oldest queued scan has waited |
| `arachne_agents{status}` / `arachne_agent_heartbeat_age_seconds{agent}` | gauge | fleet health |
| `arachne_proof_findings_total{level}` | counter | findings by proof level (L1-L4) |
| `arachne_proof_state_changes_total{cleanup}` | counter | L4 state changes, by cleanup status |
| `arachne_api_requests_total{method,status}` / `arachne_api_request_duration_seconds{method}` | counter / histogram | API traffic and latency |
| `arachne_feed_age_hours{feed}` / `arachne_feed_stale{feed}` / `arachne_feed_records{feed}` | gauge | feed freshness |
| `arachne_retention_planned_total{category}` / `arachne_retention_deleted_total{category}` | counter | pruning activity |
| `arachne_storage_used_bytes{project}` / `arachne_storage_quota_ratio{project}` | gauge | per-tenant storage |
| `arachne_evidence_bytes_total{backend}` / `_stored_bytes_total` / `_dedup_hits_total` | counter | evidence written, stored, deduplicated |
| `arachne_build_info{version,schema_revision}` | gauge | always 1; identifies the build |

Counters are **per process** (scrape every worker); the gauges listed as "the deployment" are
read from the database at scrape time, so any worker's scrape is complete. Useful alerts:
`arachne_scans{status="failed"}` rising, `arachne_queue_oldest_age_seconds` growing without
`arachne_queue_leases` moving, `arachne_agent_heartbeat_age_seconds > 120`,
`arachne_feed_stale == 1`, `arachne_storage_quota_ratio > 0.9`, and
`rate(arachne_evidence_dedup_hits_total[1h]) == 0` while evidence bytes climb.

`arachne metrics` prints the same exposition without a running server (useful for a cron check
or a support ticket); `arachne metrics --names` lists the families.

### 23.6 Traces: opt-in, sampled, best-effort (REQ-OPS-004)

```
ARACHNE_TRACING_ENABLED=true
ARACHNE_OTLP_ENDPOINT=https://otel-collector.example.com:4318
ARACHNE_TRACING_SAMPLE_RATIO=0.1
ARACHNE_OTLP_ALLOW_PRIVATE_IPS=false      # a collector on an internal address
```

One span per pipeline step (`scan.step.recon`, `scan.step.checks`, …) with the scan id and the
attempt, and one per HTTP request (`http.GET`) nested under the step that made it, carrying the
redacted URL and the status. The W3C `traceparent` header is propagated outbound, so a
target-side observer and your collector can join the two halves. Attribution says **what a scan
did**, not what it found: attributes go through the redactor, so a URL in a span cannot carry a
credential.

Sampling is decided once per trace (at the root span), so a trace is never partial. A trace
collector that is down, slow or refusing is logged and dropped — tracing observes the scan and
is never part of it. Set `ARACHNE_TRACING_SAMPLE_RATIO=1.0` while debugging a deployment, then
put it back.

### 23.7 No default credentials (REQ-OPS-006)

The compose stack ships **no** credentials. `docker compose up` stops with an explanation
unless you supply them:

```bash
cat >> .env <<EOF
POSTGRES_PASSWORD=$(openssl rand -hex 24)
ARACHNE_API_KEYS="ops-admin:admin:$(openssl rand -hex 32)"
EOF
docker compose -f docker/docker-compose.yml up -d
```

`python -m arachne.tools.credentials_gate` is the CI gate that keeps it that way: it greps the
shipped deployment surface for credential-named settings holding a literal value, compose
`${VAR:-default}` fallbacks and written-down API keys, with the vulnerable-by-design lab
fixtures exempted *per service and proved to be lab fixtures*. Run it in a pre-commit hook if
you extend the compose file.

### 23.8 What to do when storage runs out

1. `arachne retention status` — which tenant, how much, against which quota.
2. `arachne retention plan` — what a pruning run would remove, per project and category. If a
   category is empty, its policy is either `0` (keep for ever) or a legal hold.
3. Lower a policy (`arachne retention policy --project acme --evidence-days 30`) or raise the
   quota (`arachne retention quota --project acme --bytes 100GiB`).
4. `arachne retention prune --apply`.
5. If a scan was stopped by the quota, `arachne scan --resume <id>` continues it.
6. If the *object store* is full rather than the database, the pruning run unlinks the objects
   its rows referenced — the same run, the same plan.

## 24. Agentic reasoning (S21, area AGENT)

The hypothesis engine reasons like an attacker **inside the built-in cage**: it proposes
additional checks, but every proposal is executed through the planner/orchestrator under a
per-scan budget, and every decision is recorded so it can be replayed offline. Nothing here
changes the safety posture — scope, attestation, the proof ladder and redaction apply exactly as
everywhere else, and REQ-AGENT-005 makes the boundaries absolute.

### 24.1 Enabling it

| Setting | Meaning |
|---|---|
| `ARACHNE_HYPOTHESES=off\|heuristic\|hybrid\|ai` | Deployment default. `off` (the default) means the pipeline is exactly the pre-S21 pipeline: no hypothesis step, no extra request, no extra audit line. |
| `--hypotheses MODE` (per scan) | Overrides the default for one scan (`off`, `heuristic`, `hybrid`, `ai`). |
| `ARACHNE_HYPOTHESIS_MAX` | Hypotheses one scan may execute (default 5). |
| `ARACHNE_HYPOTHESIS_MAX_PROBES` | Requests those hypotheses may cost, from each check's planned estimate (default 50). |
| `ARACHNE_HYPOTHESIS_MAX_PROPOSALS` | Proposals one reasoning pass may return (default 32) — bounds a hostile input. |
| `ARACHNE_HYPOTHESIS_VERIFY_BELOW` | Below this confidence (or without a re-verification) a finding earns a confirming hypothesis (default 70). |
| `ARACHNE_HYPOTHESIS_CONTROL` | The kill switch's file (default `.arachne/hypothesis-control.json`). |
| `ARACHNE_PROOF_APPROVED` / `options.proof_approved` | Check ids the operator approves at L2+; L3/L4 additionally need the attestation's state-change authorization. |

Modes: `heuristic` never calls a model (the parity requirement's operating point); `hybrid` asks
the model *and* keeps the heuristic reading, merged model-first; `ai` uses the model's proposals
and falls back to the heuristic engine when the stage fails. A failed or unavailable provider is
recorded (`heuristic_fallback:…`) — it costs quality, never hypotheses and never safety.

### 24.2 Reading a run

```bash
arachne reason status 42            # proposals, decisions, reason codes, budget
arachne reason status 42 --json > journal.json
arachne reason replay 42            # re-derive it offline; exits non-zero if the record is broken
arachne reason replay --file journal.json --json
```

`reason status` prints one line per decision with its outcome and reason: `executed`,
`skipped`, `refused` (with a code such as `unknown-check`, `unknown-asset`, `out-of-scope`,
`approval-required`, `proof-not-attested`, `budget-exhausted`) or `deferred`. **A refusal is the
cage working**: it is recorded, audited (`hypothesis.refused`) and visible, never silently
dropped. `reason replay` needs no target, no database and no provider — it recomputes the input
hash, checks every decision against its proposal, and re-runs the heuristic engine.

The API exposes the same journal (`GET /api/v1/scans/{id}/hypotheses`) and one audit line per
proposal pass (`hypothesis.proposed`) plus one per decision.

### 24.3 Stopping a run (REQ-AGENT-007)

```bash
arachne reason pause 42             # stop this scan between two hypotheses
arachne reason abort 42
arachne reason abort --all          # a deployment-wide stop, not cleared by a resume
arachne reason resume 42            # clear a directive so `arachne scan --resume` continues
```

The directive is a file (`ARACHNE_HYPOTHESIS_CONTROL`) because the scan may be running on another
node in another process; the step reads it before *each* hypothesis, so an in-flight probe
finishes and nothing new starts. The journal keeps the proposals and the cursor, so
`arachne scan --resume <id>` continues exactly where it stopped. A directive set for one scan is
cleared by that scan's resume; `--all` is not. The API mirror is
`POST /api/v1/scans/{id}/hypotheses/control` with `{"directive": "pause"|"abort"|"none"}`.

### 24.4 Attack paths in the report

A scan's report gains `## 9. Attack paths` (JSON: `attack_paths`, schema 1.6): every chain the
findings compose on one host, the **terminal** hop's impact as the path's severity, each hop with
its evidence and a *verified* or *candidate* marker, and the cheapest remediation that breaks the
chain. A candidate hop names the check that would verify it, and a path with one is reported as
partially verified — the report never presents an unproven link as a proven one.

## 25. False-positive workflow, suppressions and risk acceptance (S21, area QUAL)

Three records, three different meanings — and the distinction is the point:

| Record | Says | Lifetime |
|---|---|---|
| **FP mark** (`arachne fp mark`, `PATCH /findings/{id}`, the finding's *Mark false positive* action) | "this finding is not real" | feeds the per-check confidence tuner (S5) |
| **Suppression rule** (`arachne quality suppress`) | "findings of this check / on these assets are not reported" | until revoked or expired; versioned, attributed, commented |
| **Risk acceptance** (`arachne quality accept`) | "this finding is real, and *owner* accepts it until *date*" | until the date, then the finding re-opens automatically |

### 25.1 Suppression rules

```bash
arachne quality suppress --check m3.security-headers \
  --reason "the reverse proxy sets the headers; the scanner sees the origin" --days 90
arachne quality suppress --check m3.xss-oracle --asset 'https://app.example/*' --reason "escaped upstream"
arachne quality suppress --check m3.xss-oracle --finding 42 --reason "this instance is a test fixture"
arachne quality suppressions [--all] [--json]
arachne quality unsuppress 3
```

A reason is required (minimum length) and the actor is recorded: a suppression is a decision
somebody owns. Every rule gets the next version from one monotonic sequence, so a report can
cite "suppressions v7". Re-scan diffs exclude suppressed **new** findings and always state the
count and the version — `12 new · 1 fixed · … · 2 suppressed`. A finding that was already known
and is now suppressed stays in `recurring`: a rule is not a fix. The API and the `/ui/quality`
page write the same records (REQ-QUAL-001).

### 25.2 Risk acceptance

```bash
arachne quality accept --finding 42 --owner platform-team \
  --justification "compensated by the network control" --days 30
arachne quality acceptances [--finding 42] [--all]
arachne quality withdraw 7
arachne quality expire          # re-open every finding whose acceptance lapsed
```

Owner, justification and an expiry are mandatory. `expire` is explicit rather than a background
daemon — a cron job, a scan's admission, an operator or the API's
`POST /api/v1/acceptances/expire` decides *when* the clock is checked — and each re-open is
audited (`acceptance.expired`) and stamped on the acceptance.

### 25.3 FP-rate trends

```bash
arachne fp trends --days 30 --alert 0.1
```

Per (check, asset kind, signature): marks, false positives, the rate over the window and the rate
over the recent buckets, plus an alert for any key whose recent rate rose by more than the
threshold (with a minimum number of marks, so a 1/1 rate is not an alert). This is the process
view of the same `fp_feedback` rows the tuner aggregates.

## 26. Benchmark harness (S21, REQ-QUAL-005)

```bash
python -m arachne.tools.benchmark --lab                 # measure the in-repo ground-truth lab
python -m arachne.tools.benchmark --lab --gate          # the CI job: fail on a regression
python -m arachne.tools.benchmark --lab --gate --write-baseline
python -m arachne.tools.benchmark --suite juice-shop --target http://localhost:3000/ --gate
python -m arachne.tools.benchmark --json                # machine-readable report
```

A suite (`templates/benchmark/suites/<name>.yaml`) is a versioned list of cases: a `tp` case is a
marker that must appear in a check's evidence, an `fp` case is a hardened counterpart that must
not be reported. Scoring counts only the suite's cases; a finding on a path the suite does not
describe is reported as **unscored** rather than counted as a false positive, because the suite's
exhaustiveness is not the scanner's precision.

Results are committed under `benchmarks/<suite>/baseline.json` (suite version, Arachne
version, target, score). `--gate` compares a run against that baseline and exits non-zero on a
detection drop or an FP-rate rise beyond the tolerances (`--max-detection-drop`,
`--max-fp-rise`), and refuses to compare across suite versions.

**The published artifact is reproducible (WP-19, REQ-TRUST-010).** A committed result now
carries the four things the claim needs — the **corpus version** (and its digest), the exact
**command**, the **environment** (interpreter, platform, build epoch) and **raw per-case rows**,
plus precision, recall and a per-case time-to-finding whose source is named — in
`benchmarks/<suite>/results.json`, described suite by suite in `benchmarks/README.md`. The
method, the degenerate cases and the reproduction procedure are in
`docs/reproducible-benchmark.md`. Fixture rotation is recorded (`rotated_at`/`review_by` per
suite) and a test fails when a suite is past its review date.

| Suite | Source | Runnable here |
|---|---|---|
| `arachne-lab` | the repository's own ground-truth lab | yes — this is what CI gates on |
| `owasp-benchmark`, `juice-shop`, `dvwa` | hosted targets | no: suite + `reproduce` command shipped; commit a baseline after running them against the real target |

The CI job is `benchmark` in `.github/workflows/ci.yml`
(`python -m arachne.tools.benchmark --gate --lab`). A planted detection regression turns it red:
`tests/unit/test_benchmark.py::test_a_planted_regression_turns_the_benchmark_job_red` runs the
gate against a temp baseline that claims a better score than the run achieves and asserts a
non-zero exit.

## 27. Feed-driven check synthesis (S21, REQ-AGENT-004)

```bash
arachne synthesize propose --feed kev --limit 25 --out .arachne/proposals
arachne synthesize list
arachne synthesize review m2.cve-2021-44228-apache-log4j --reviewer alice \
  --parity-suite arachne-lab --parity-ok
```

`propose` turns active threat-intel rows into one reviewable artefact directory per candidate
check: `check.yaml` (the catalogue row), `test_proposed_check.py` (a scaffold that *fails* until a
developer implements the fixtures), `REVIEW.md` (the checklist) and `proposal.json`. Versions are
bumped (MINOR for an existing check, `0.1.0` for a new one), and every proposal records the
catalogue version it was generated against.

**Nothing here deploys.** There is no code path from a proposal into the live registry, the
artifact writer refuses the shipped catalogue directory, and `review` refuses to approve without
a passing parity result and a named reviewer. A human merges the catalogue row and implements the
check.

## 28. Compliance frameworks & the evidence export (S22, area TRUST)

```bash
arachne compliance frameworks
ARACHNE_REPORT_COMPLIANCE_FRAMEWORKS=iso27001,pci-dss arachne report --scan 7 -o report.md
arachne compliance export --scan 7 --framework iso27001 -o iso-evidence.json
```

Four frameworks ship: **CIS Controls v8.1**, **PCI DSS v4.0**, **ISO/IEC 27001:2022 Annex A**
and **NIST CSF 2.0**. Each maps check ids onto the controls a finding is evidence about —
`m3.sqli-oracle` speaks to ISO A.8.25, `m2.tls-deep-scan` to PCI 4, and so on.

**The maps are generated, not maintained (WP-19, REQ-TRUST-009).** The source of truth is each
check's `compliance=` declaration in `src/arachne/modules/`, validated at import against a
pinned, complete inventory of the framework (`src/arachne/data/compliance/*.json` — each one
records its source, retrieval date and cross-check). `python -m arachne.tools.compliance --write`
regenerates the four YAML files and `--check` fails when a committed map and the registry
disagree, so hand-editing a map is a build failure rather than a silent drift:

```bash
python -m arachne.tools.compliance            # the ratios and targets
python -m arachne.tools.compliance --check    # exit 1 when a map is stale
```

The reach, counted from the registry: **CIS 64 of 153 safeguards, ISO/IEC 27001 46 of 93
controls, NIST CSF 42 of 106 subcategories, PCI DSS 11 of 12 requirements.** PCI requirement 9
(physical access to cardholder data) is the exception and is *named*, not claimed: no check
produces an artefact for facility entry, media handling or point-of-interaction tampering, and
the map lists it under `outside_assessed_set` with that reason.

Every unmapped control is listed there — `assessed + outside` is always the framework's own
total — so a report can never be read as "the framework is covered". The same list travels in
`arachne compliance export`, so an auditor sees exactly what no check can speak to.

Turning a framework on (`ARACHNE_REPORT_COMPLIANCE_FRAMEWORKS=cis,pci-dss,...`, a
comma list, or per-report `--framework` on the export) adds an appendix section to every
report. Read it like this:

- **fail** — a mapped check produced a confirmed finding. The control is not operating as
  intended, and the finding ids travel with the row.
- **pass** — mapped checks ran and found nothing.
- **gap** — the control's mapped checks did not run in this scan (opt-in withheld, module
  off, target not applicable). A gap is *not* a clean result; the section names exactly
  which checks were not run.

Every framework header states the **mapped vs. total** control count — PCI DSS's 12
requirements, ISO 27001's 93 Annex A controls, CIS v8.1's 153 safeguards, NIST CSF 2.0's
106 subcategories — so the unmapped remainder is an explicit statement in the report, not
an implication of coverage. Findings are evidence about a control's operation; they are
not proof of conformity with a management-system standard, and the report says so.

`arachne compliance export` writes the audit-ready per-control evidence document: one
self-contained JSON file with the framework's identity (edition, map version, source),
the scan's identity (including the attestation), every control's state, the failing
findings **and their redacted evidence payloads inline**, and the audit-trail summary.
Nothing is re-derived later: attach the file to the audit ticket and it stands alone.

Custom maps: point `ARACHNE_REPORT_COMPLIANCE_MAPS` at a directory with your own
`<framework>.yaml` (override a bundled one by name or add another). The same schema test
validates a supplied reference set; report time treats an unknown check id as "never ran"
(an honest gap) rather than failing the report. A generated map carries an
`outside_assessed_set` block; the loader refuses a map whose assessed and outside sets do not
add up to the framework total, so a custom map cannot quietly drop a control either.

## 29. Integrations: DefectDojo, Jira, ServiceNow, SIEM, chat (S22, area OPS)

All outbound integrations share the S12 webhook machinery and its three non-negotiables:
egress goes through the scoped, rate-limited, audited HTTP client; every token is a
`SecretStr` read only to build the auth header; **a delivery failure never fails a
scan** — it is audited (`webhook.failed`) and returned. Delivery order is stable
(slack, teams, jira, servicenow, defectdojo, siem).

| Integration | Settings (env) | What is sent |
|---|---|---|
| Slack / Teams | `ARACHNE_WEBHOOK_SLACK_URL`, `ARACHNE_WEBHOOK_TEAMS_URL` | one summary card: counts, top findings, report link |
| Jira | `ARACHNE_WEBHOOK_JIRA_URL` + `_JIRA_PROJECT` + `_JIRA_TOKEN` (+ `_JIRA_USER` for Cloud Basic) | one issue per finding at/above `ARACHNE_WEBHOOK_MIN_SEVERITY`, capped by `_MAX_FINDINGS`, priority mapped from severity |
| ServiceNow | `ARACHNE_WEBHOOK_SERVICENOW_URL` + `_SERVICENOW_USER` + `_SERVICENOW_PASSWORD` | one incident per at-or-above-threshold finding via the Table API (`/api/now/table/incident`), impact/urgency mapped from severity; the URL is refused without credentials |
| DefectDojo | `ARACHNE_WEBHOOK_DEFECTDOJO_URL` + `_DEFECTDOJO_TOKEN` | an `import-scan` push to `/api/v2/import-scan/` with `close_old_findings` |
| SIEM | `ARACHNE_WEBHOOK_SIEM_URL` + optional `_SIEM_TOKEN` | newline-delimited JSON (`application/x-ndjson`): one `scan.summary` record, one record per finding, one record per audit event |

DefectDojo is the first integration target and gets the offline path too:

```bash
arachne report --scan 7 --format defectdojo -o import-me.json
```

produces **exactly the document the webhook posts** (one shared builder,
`arachne.report.defectdojo`) — hand it to DefectDojo's UI or its API from a deployment
that cannot egress to DefectDojo directly. The SIEM export carries the scan's audit
trail alongside the findings; the trail's own dicts are already redacted at capture, and
the audit reader is fetched per scan so the export is a point-in-time artifact.

Enable the machinery with `ARACHNE_WEBHOOKS_ENABLED=true`. Contract tests
(`tests/unit/test_integrations_contracts.py`) pin every payload against recorded
receiver-side documents in `tests/fixtures/integrations/`; the no-secrets-in-logs test
proves none of the tokens reaches a payload body, the audit trail, or the log stream.

## 30. Deployment: Helm chart, HA and secrets (S22, REQ-OPS-005)

`deploy/helm/arachne` deploys the whole control plane:

```bash
helm install arachne deploy/helm/arachne \
  --set postgres.auth.password="$(openssl rand -hex 24)" \
  --set api.auth.apiKeys="ops-admin:admin:$(openssl rand -hex 32);agent:scanner:$(openssl rand -hex 32)" \
  --set agent.auth.apiKey="agent:scanner:$(openssl rand -hex 32)"
```

- **API** — `api.replicas: 2` (HA) with a PodDisruptionBudget and preferred node
  anti-affinity; `api.workers` is the uvicorn worker count *inside* each pod
  (`ARACHNE_API_WORKERS`, `arachne serve --workers N`). Scale pods for availability,
  workers for per-pod CPU. Counters stay per worker (S20 §23): Prometheus sums the
  replicas' scrape targets; gauges are database-derived.
- **Agent pool** — `agent.replicas` distributed-mode workers leasing from the queue
  (§18); `agent.mode: internal` marks an in-target pool (§22).
- **Postgres** — a StatefulSet with a PVC, or `postgres.enabled: false` plus
  `--set databaseUrl=...` for a managed instance. The password is only ever a
  `secretKeyRef`.
- **Migration** — `arachne db upgrade` as a `pre-install,pre-upgrade` hook Job; the
  schema is current before the API rolls.
- **Evidence** — `evidence.backend: local` (a shared ReadWriteMany volume) or `s3`
  (§23).

**Secrets come from env, files, or Vault.** The chart ships *no* credentials
(REQ-OPS-006): `helm install` fails the render until `postgres.auth.password` and the API
keys exist. Three sources: values (`secretEnv`, your own release values — never
committed), a Secret you manage (`existingSecret`, mounted read-only as a key file), or
Vault Agent injection (`vault.podAnnotations` carries the injector annotations; ARACHNE
reads the injected files via `ARACHNE_API_KEYS_FILE` and friends). `helm lint` and a
render smoke run in CI with generated throwaway values.

## 31. Supply chain: SBOM, signing, provenance (S22, REQ-TRUST-002/003)

A tagged release (`v*`) runs `.github/workflows/release.yml`, which

1. runs `pip-audit --strict` **as a release blocker** (on ordinary pushes CI's
   `dependencies` job stays advisory);
2. generates the CycloneDX 1.5 SBOM with `python -m arachne.tools.sbom` **and validates it
   against the vendored official schema** before attaching it to the release (WP-19);
3. builds the image, pushes it to GHCR **by digest**, signs the digest with **cosign
   keyless** (the signature's identity is the repository's GitHub OIDC claim — there is
   no long-lived key to rotate or leak), and attests the SBOM to the same digest;
4. generates **SLSA v1.2 Build L3** provenance with `actions/attest-build-provenance` (the
   GitHub-hosted runner is the hardened build platform and signs the provenance with the
   workflow's OIDC identity), then verifies its own attestation round-trips with cosign.

Verify before you deploy:

```bash
cosign verify <image>@<digest> \
  --certificate-identity-regexp '^https://github.com/<owner>/<repo>/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
cosign verify-attestation --type slsaprovenance1 <image>@<digest> \
  --certificate-identity-regexp '^https://github.com/<owner>/<repo>/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify oci://<image>@<digest> --repo <owner>/<repo>
```

Tool versions are pinned (cosign via `COSIGN_VERSION`, actions by major tag,
`pip-audit` bounded in the `audit` extra); `docs/reproducible-builds.md` documents
the build's deterministic and non-deterministic parts and how to reproduce an image.
The SBOM is a product artifact: any operator can run the generator against their own
installed environment, and its output is byte-identical for the same environment and
timestamp (`SOURCE_DATE_EPOCH` honoured). `python -m arachne.tools.sbom --check <file>`
validates any CycloneDX 1.5 document offline.

**Local provenance, and its limits.** `python -m arachne.tools.provenance` emits the same
SLSA v1.2 in-toto statement for artefacts you build yourself, and `--verify` re-derives every
subject digest — useful for an air-gapped or self-hosted build. It is **not** SLSA Build L3:
nothing isolates the builder and nothing stops the document being edited afterwards, so it
defaults to an honest local builder id rather than impersonating a platform.
`docs/slsa-provenance.md` states exactly which L3 requirements each path does and does not
meet.

## 32. Continuous exposure management (S23, area POSTURE)

Continuous mode turns ARACHNE from a point-in-time scanner into a watcher: cloud-config
state is collected on a schedule, diffed against the last baseline, and the fix loop
closes and re-opens findings as the estate actually changes. Everything below composes
with the existing gates — a continuous scan is admitted through the same scope,
authorization and proof gates as any other scan, and the hard rules hold: **read-only
against cloud control planes, no enforcement action by default**.

### 32.1 Continuous cloud-config schedules (REQ-POSTURE-001)

`m5.cloud-posture` reads a cloud-config **state snapshot** with one bounded read-only
GET. The canonical input is the normalized export
(`{"provider": ..., "resources": [{"id", "service", "type", "config", ...}]}`) served by
a read-only collector endpoint; the AWS `DescribeSecurityGroups`, Azure `List` and GCP
`aggregatedList` read-only response shapes are parsed directly. Declare the snapshot as
a URL target (or `endpoint:<url>`); a provider reference alone names no host, so the
requests the check may make are exactly the declared prefix. An optional bearer token
rides `ARACHNE_M5_POSTURE_TOKEN` (environment only, never logged).

A continuous schedule is a normal schedule marked `continuous: true`:

```json
{
  "id": "estate-watch",
  "target": "examples/targets/lab-fixture.yaml",
  "cron": "0 * * * *",
  "continuous": true
}
```

The first run commits the baseline (no deltas — the estate appearing wholesale is the
baseline being established, not drift). Every later run emits **delta findings** for
what changed, each artifact carrying `before`/`after` and the changed keys; a change
that introduces a policy breach is a finding, other changes are recorded observations.
Estate policies live in the M5 corpus (`posture.policies` — id, severity, the config key
and the value that breaches) and are evaluated on every run.

### 32.2 Cost guardrails: schedule budgets (risk R-13)

A continuous schedule inherits the deployment budget (`ARACHNE_POSTURE_MAX_RUNS_PER_DAY`,
default 24; `ARACHNE_POSTURE_MAX_REQUESTS`, default 5000 estimated requests per run) or
carries its own:

```json
{
  "id": "estate-watch",
  "target": "examples/targets/lab-fixture.yaml",
  "cron": "*/10 * * * *",
  "continuous": true,
  "budget": {"max_runs_per_day": 6, "max_estimated_requests": 500}
}
```

A run past the daily cap — or a run whose offline dry-plan estimates more requests than
the cap — is **refused and audited** (`schedule.budget_refused`); it never silently
skips. The window history lives in the scheduler state file and is carried across
status updates.

### 32.3 The IaC/CI gate (REQ-POSTURE-002)

`arachne iac-gate PATH` reviews a local tree of Terraform, Kubernetes manifests and CI
pipeline configs through a **real scan** (M5's artifact reviews, offline by
construction), so findings carry the same schema, evidence and check provenance as any
scan. Exit codes are the CI-gate policy (F-07-05): `0` clean, `1` findings below the
threshold, `2` at least one at/above (`--fail-on high` by default,
`ARACHNE_CI_FAIL_ON` to set it in the environment):

```bash
arachne iac-gate infra/ --fail-on high          # in CI: blocks the deploy on high+
arachne iac-gate infra/ --json                  # machine-readable gate block
```

The scan's attestation is the invocation itself ("local pre-deploy review of <path>; no
network requests") and is recorded like any other. The structured Kubernetes policy
rules the gate runs are the **same rules the admission webhook enforces** — what the
gate blocks and what the cluster refuses cannot drift apart.

### 32.4 K8s admission mode (REQ-POSTURE-005)

The API exposes `POST /api/v1/admission` implementing the Kubernetes AdmissionReview v1
protocol. Wire a `ValidatingWebhookConfiguration` to it with a dedicated service
account key (route auth is the standard API key). Posture:

- **monitor** (the default): every review is evaluated, every request **allowed**; the
  findings ride the response's `status.message` and the `admission.reviewed` audit line.
- **enforce** (opt-in): denies only when violations at/above
  `ARACHNE_ADMISSION_DENY_ON` (default `high`) occur **inside the staged namespace
  list** (`ARACHNE_ADMISSION_ENFORCE_NAMESPACES`; `*` is the explicit all-namespaces
  form). An empty list denies nothing. Staged rollout: monitor → enforce with one
  namespace → widen → `*`.
- **off** (`ARACHNE_ADMISSION_MODE=off`): the route refuses — a mispointed webhook fails
  loudly.

Rehearse without a cluster (`arachne posture admission-check manifest.yaml --mode
enforce`): the same engine, the same decision, exit `0` allowed / `2` denied. Internal
evaluation errors **fail open** (availability of the cluster outranks ARACHNE's opinion)
with the error audited.

### 32.5 The fix-verification loop (REQ-POSTURE-003)

```bash
arachne posture verify-fix 42     # targeted re-scan of ONLY the affected checks
arachne posture reconcile --scan 17   # reopen regressions after a manual scan
```

`verify-fix` re-runs the original scan's admitted request bounded to the affected check
(`ModuleSelection.only`), through every gate. Verified absence **auto-closes** the
finding (status `closed`); the check still reporting it keeps it open with the act
recorded. A later scan of the same target that reports the same `(check, asset)` again
**auto-reopens** the original finding — the scheduler runs the reconciliation after
every scheduled scan, and `posture reconcile` on demand. Every act writes
`posture_verifications` and links its evidence to the **original** finding, so the
record reads "closed by verification scan N / reopened by scan M".

### 32.6 Estate posture & trend report (REQ-POSTURE-004)

```bash
arachne posture report --project acme            # executive markdown
arachne posture report --json                    # dashboard payload
```

Trend (severity counts per scan), drift per period (new/fixed/regressed/recurring), the
fix-verification loop's numbers, and the watched inventory (resources by service per
continuous scope) — all from stored data, no re-scan.

### 32.7 CMDB criticality (REQ-POSTURE-006, optional)

```bash
arachne posture cmdb import cmdb.csv        # host,tier[,name] — tier 1 is most critical
```

Imported tiers feed attack-path **ranking and labelling**: a tier-1 asset's path ranks
(and renders) at its business floor (tier 1 ⇒ at least high) with a
`Business impact: tier 1 …` line in the report. Finding severities are never re-scored.
Wildcards (`*.example.com`) cover subdomains without an exact row.

## 33. Detection validation: the purple team (S24, area VALID)

Everything ARACHNE proves about *possibility* — the S15 proof ladder — can be turned into
a question about *detection*: would the defender's controls have seen it? Purple mode
replays the same safe proof actions as a **detection test**, inside a time window agreed
with the defender, with every emitted artifact carrying a visible run nonce, and compares
what was emitted against what the defender's SIEM reported.

**The hard rule of the area: these tests are designed to be SEEN.** No evasion, no stealth,
no offensive tooling. Payloads are the ladder's own declared payloads (a calm marker, an
out-of-band token, one allowlisted `echo`), emitted verbatim under the ordinary rate limit,
inside the window. A test that cannot be distinguished from an attack is not a test this
project runs, and `tests/unit/test_purple_attack.py::test_no_evasion_anywhere_in_the_purple_package`
fails the build if evasion-capable code ever appears in the package.

**What is replayable, and against which taxonomy (WP-19, REQ-VALID-007).** The catalogue
(`src/arachne/templates/purple/attck-map.yaml`, override with `ARACHNE_PURPLE_MAP`) covers
**41 actions exercising 36 ATT&CK Enterprise v20 techniques across 10 tactics** — from active
scanning and credential discovery through injection, cloud-storage collection and defense
impairment. Every entry names a registered check and the proof level the catalogue declares for
it; the planner refuses a map that disagrees with the registry, so an action cannot claim to sit
lower on the ladder than it does.

The vocabulary is the release's, not a hand-kept list: the pinned snapshot carries ATT&CK v20's
complete technique set (706 techniques) and its **15 tactics**, in which Defense Evasion no
longer exists — v20 split it into **Stealth** and **Defense Impairment**. An action's technique
must exist in the release, and the tactic it files itself under must be one the release assigns
that technique. **No action is filed under Stealth**: these tests are designed to be seen, and
filing one there would describe an evasion capability the product refuses to have. (ATT&CK
assigns T1078 Valid Accounts Stealth among four tactics; the catalogue uses its
initial-access/persistence assignment for a plain logon test.) A map violating either rule is
refused when it is loaded, operator overrides included.

### 33.1 The coordinated window: an attestation class (REQ-VALID-001)

A purple run needs an attestation that carries a **detection window** — the interval both
sides agreed, who coordinated it and who is watching:

```yaml
target:
  name: lab-web
  targets: [{kind: url, value: "https://app.example.com/"}]
  attestation:
    attested_by: "Jane Operator <jane@example.com>"
    attested_at: "2026-10-31T06:00:00Z"
    scope_statement: "coordinated purple-team window over the app"
    allowed_targets: ["https://app.example.com/"]
    active_checks_authorized: true      # purple replays active proof actions
    expires_at: "2026-10-31T18:00:00Z"
    detection_window:
      starts_at: "2026-10-31T12:00:00Z"
      ends_at:   "2026-10-31T13:00:00Z"
      coordinator: "soc-lead@example.com"
      defender: "blue-team@example.com"
      reference: "CHG-4242"
```

Three enforcement points, all audited:

* **The window must sit inside the authorization** (it may not start before `attested_at`
  nor end after `expires_at`) — a test can never outlive its authority.
* **Purple mode without a window is refused at the authorization gate** (`auth.rejected`):
  no window, no detection test.
* **The window is re-checked at plan, at execute and at resume**, and the run *stops
  itself* when the window closes mid-run: the remaining actions are skipped and the stop is
  audited once (`purple.window_closed`). A refusal is `purple.window_refused` with the
  window and the moment, and a refused plan creates **no scan row and sends nothing**.

### 33.2 Defining and running a campaign (REQ-VALID-001/006)

```bash
arachne purple campaign add nightly-web \
  --target lab-web \
  --action m3.sqli-oracle --action m3.cmdi-oob --action m3.state-marker \
  --cron "0 2 * * 3"          # weekly; omit --cron for manual runs
arachne purple campaign list
arachne purple campaign run nightly-web      # 0 completed · 2 refused (window/unknown)
```

The replayable actions and the ATT&CK technique each one exercises are **shipped data**
(`templates/purple/attck-map.yaml`, override with `ARACHNE_PURPLE_MAP`). The map cannot
lie about the ladder: an action naming a check that does not exist, or claiming a proof
level the catalogue does not declare, is refused at plan time. `--action` values are the
proof checks — see `m3.sqli-oracle` (L1), `m3.sqli-oob`/`m3.xxe-oob`/`m3.cmdi-oob`/
`m3.ssti-oob` (L2), `m3.rce-echo` (L3), `m3.state-marker` (L4).

A scheduled campaign is a normal schedule with `purple_campaign`:

```bash
arachne schedule add --id purple-weekly --cron "0 2 * * 3" --purple-campaign nightly-web
```

The scheduler's budgets, run history and the campaign's own window gate all apply; a
refused run is *recorded* (`status: window_refused`) so the trend shows it rather than the
schedule silently breaking.

### 33.3 SIEM ingest: webhook, pull or export (REQ-VALID-002)

Alerts arrive one of three ways; all three land in the same normalized shape.

**Webhook** (the SIEM's forwarder posts to ARACHNE — one alert, `{"alerts": [...]}`, or
newline-delimited JSON, the content type ARACHNE's own SIEM webhook destination emits):

```bash
curl -X POST https://arachne.example.com/api/v1/purple/alerts \
  -H "Authorization: Bearer <scanner-api-key>" \
  -H "Content-Type: application/json" \
  --data @alerts.json
# → {"accepted": 5, "new": 5, "duplicates": 0, "source": "webhook:siem"}
```

An alert needs a **timestamp** (RFC 3339, timezone required) and is otherwise tolerant: a
technique may appear as `technique`, `technique_id` or `attack_technique` (`attack.t1059`
and `T1059` both work), the run nonce may appear as a `nonce` field, inside an ARACHNE
callback token, or as a `nonce=<value>` pair in the message. A bare hex-looking string in
prose is deliberately *not* treated as a nonce — it could be a file hash, and counting it
would inflate coverage. Re-delivered alerts are deduplicated on `(source, alert_id)`.

**Pull** — the deployment points ARACHNE at the SIEM instead:

```bash
ARACHNE_PURPLE_ALERTS_URL=https://siem.example.com/api/alerts     # ?since=&until= appended
ARACHNE_PURPLE_ALERTS_TOKEN=<bearer>                              # environment only
```

A campaign run then collects the last seven days' alerts through the shared scoped HTTP
client (pinned to that host, ADR-05) before scoring. A failing SIEM never fails the run:
the coverage scores against what has arrived and the failure is audited.

**Export** (air-gapped, or after the fact):

```bash
arachne purple alerts ingest --file siem-export.ndjson --source lab-siem
arachne purple alerts list
```

### 33.4 Reading the results (REQ-VALID-002/004/005)

```bash
arachne purple score nightly-web            # re-score against the alerts so far
arachne purple report nightly-web           # the defender report (markdown)
arachne purple report nightly-web --json --output defender.json
arachne purple trend nightly-web            # coverage over time + regression alerts
```

An emission counts as **seen** only when an alert names a matching technique *and* carries
**this run's nonce** *and* falls inside the window. Anything less is reported separately,
because flattering the number is the one thing a coverage report must not do:

| Alert | Read as |
|---|---|
| technique + this run's nonce + in window | **seen** |
| technique, no nonce (or another run's) | `unlinked` — the SIEM fired, not provably for us |
| technique, outside the window | `out of window` — the defender was not watching yet |
| a technique nothing emitted | `other techniques` — the defender's own traffic |
| no ATT&CK technique | `without a technique` |

The report renders control coverage (per technique and % per ATT&CK tactic, plus the
explicit gap list), the **Sigma alignment** against the M6 hunt library (rule-hit /
rule-miss per action — a rule-miss is a gap in the rule set, stated as such), and
**"what an attacker could do unseen"**: the S21 attack paths whose hops exercise techniques
the defender provably does not see. A hop whose check has no technique mapping is reported
as *unmapped*, not as blind — the report must not overclaim.

Recurring campaigns track coverage over time; a technique that was seen in the previous run
and is unseen now is a **regression** (`purple.coverage_regressed`, listed by
`arachne purple trend`).

### 33.5 Configuration reference (S24)

| Variable | Meaning | Default |
|---|---|---|
| `ARACHNE_PURPLE_ALERTS_URL` | SIEM pull endpoint (unset = no pull) | unset |
| `ARACHNE_PURPLE_ALERTS_TOKEN` | bearer for the pull endpoint (env only) | unset |
| `ARACHNE_PURPLE_MAX_ACTIONS` | most proof actions one run may replay | `12` |
| `ARACHNE_PURPLE_MAX_ALERTS` | most alerts one ingest accepts | `1000` |
| `ARACHNE_PURPLE_NONCE_BYTES` | entropy of the generated run nonce | `12` |
| `ARACHNE_PURPLE_MAP` | override the shipped replay catalogue | shipped map |

The run nonce, the window, the emitted actions and their Sigma verdicts also land in the
**scan's own report** (schema 1.9, appendix I, `detection_validation`), so a purple run's
ordinary report is visibly a tagged test rather than an unexplained burst of traffic.

---

## 34. Air-gapped deployment (S25, REQ-RESIL-001)

An air-gapped estate has no route to the internet — and no route *from* it either. ARACHNE runs
the full heuristic pipeline in that estate: no provider, no feed fetch, no telemetry. Content
(the check catalogue, the Sigma rules, the CVE index) arrives as a **signed offline content
pack** an operator carries in by hand.

### 34.1 What the mode actually enforces

`ARACHNE_AIRGAPPED=true` installs a second, stricter allowlist on the shared HTTP and non-HTTP
egress paths. The reachable hosts become:

1. the deployment's **scan targets** (the deployment scope, `ARACHNE_SCOPE_*`), and
2. the hosts named in `ARACHNE_AIRGAP_ALLOWED_HOSTS` (an on-premises model server, an internal
   feed mirror).

Everything else — NVD, a CT-log provider, a cloud AI endpoint, a webhook target, an OTLP
collector, an IdP, a plugin download — is refused **at the client** and audited
(`airgap.blocked`). The refusal does not depend on each feature remembering to check a flag;
that is the point of putting it on the one egress path.

> **Configure your estate.** With no `ARACHNE_SCOPE_*` set the allowlist is empty, so *every*
> host is refused — including your scan targets. Declare the estate you are authorized to scan:
>
> ```bash
> export ARACHNE_AIRGAPPED=true
> export ARACHNE_SCOPE_HOSTS=lab.internal
> export ARACHNE_SCOPE_NETWORKS=10.20.0.0/24
> export ARACHNE_SCOPE_DOMAINS=lab.internal
> export ARACHNE_INTEGRITY_KEY=<32+ random chars>      # signs packs and the audit chain
> ```

The engine stays heuristic in this mode (no AI provider is reachable anyway), and feed sync and
provider calls are refused rather than attempted. `arachne integrity status` reports the mode.

### 34.2 Building a pack (on a connected build)

```bash
# Export content (checks, rules, CVE index, templates) as one signed archive.
arachne packs export --out arachne-baseline-2026.10.tar.gz \
    --name baseline --version 2026.10 \
    --content /path/to/reviewed/checks            # repeatable root; also --rules/--feeds

# Verify what you are about to carry in (does not install anything).
arachne packs verify arachne-baseline-2026.10.tar.gz
```

`--name`/`--version` are the pack's identity and are what the provenance row records. A pack
built without `ARACHNE_INTEGRITY_KEY` is unsigned: an importer refuses it by default, which is
deliberate — building is a local act, importing is the one that trusts.

### 34.3 Importing a pack (in the air-gapped estate)

```bash
arachne packs import arachne-baseline-2026.10.tar.gz
arachne packs list                     # what this estate is running, and who signed it
```

Import verifies the manifest's signature first, then every file's digest and size, then refuses
anything undeclared, escaping the content directory, or not a regular file. Nothing is
installed if anything fails: files are staged and renamed into place, so an interrupted import
leaves the previous version or nothing. Every import is recorded in `content_packs` (name,
version, manifest digest, signing key, what it carried, who imported it) and audited
(`pack.imported`); a refused pack is audited too (`pack.rejected`).

`--allow-unsigned` exists for a lab and is off by default.

### 34.4 Routine operation

| Task | In the estate |
|---|---|
| Scan | `arachne scan --target estate.yaml` — fully offline (heuristic engine) |
| Update content | carry a pack in, then `arachne packs import` (§34.3) |
| Update vulnerability data | `arachne feeds import` on a file an operator brings (§12) |
| Verify the trail | `arachne verify-chain` (§37) |
| Back up | `arachne dr backup --out /backup/$(date +%F)` (§36) |

### 34.5 Configuration reference (S25, air-gap)

| Variable | Meaning | Default |
|---|---|---|
| `ARACHNE_AIRGAPPED` | enable the air-gap allowlist | `false` |
| `ARACHNE_AIRGAP_ALLOWED_HOSTS` | extra hosts reachable while air-gapped | unset |
| `ARACHNE_CONTENT_DIR` | where imported packs are unpacked | `<db dir>/content` |
| `ARACHNE_CONTENT_REQUIRE_SIGNATURE` | refuse an unsigned pack on import | `true` |

## 35. High availability and zero-downtime upgrades (S25, REQ-RESIL-002)

### 35.1 Running several API replicas

The API is stateless: every replica serves the same store, so `replicas: 2` in the Helm chart
(or several `arachne serve` processes behind a load balancer) is a genuine HA deployment. What
must run **once** is the singleton work — the scheduler tick, the retention prune, the chain
anchor — and that is what the leader lease is for.

```bash
arachne dr status                 # who holds each lease, the queue depth, the scaling decision
```

A lease is a row in `leader_leases`; its holder is the replica whose identity is recorded and
whose expiry has not passed. Two replicas cannot hold one lease at the same time: the
acquisition compares-and-swaps a fencing token, so the loser's update matches no row and it
reports "not the leader" instead of double-holding. Liveness is computed from the expiry, so a
replica that is SIGKILLed hands the lease on by simply not renewing it — no cleanup step for
the killer to skip.

`arachne schedule run` (the tick loop) acquires the `scheduler` lease and skips its tick when
another replica holds it; `arachne schedule run --id X` is an explicit operator act and is never
gated, because a human asking for one schedule has already made the decision the lease exists
to make automatically.

### 35.2 Upgrading without an outage

A release's migration must be **expand-only** so the old replicas keep serving while the new
ones roll out:

```bash
arachne dr status --json        # .head_migration → {"expand_only": true, ...}
```

The checker reads the head migration's source and reports anything a rolling upgrade would not
survive: `drop_column`, `drop_table`, `drop_index`, `drop_constraint`, `rename_table`, an
`alter_column` that renames, narrows a type or sets `nullable=False`, and any opaque
`op.execute` (reported as *medium* for review). Migration 0011 is expand-only by construction:
nullable columns and new tables, nothing dropped.

The rollout:

1. Run the expand (`helm upgrade`, or `arachne db upgrade` on the first new replica) while the
   old code is still serving. Pre-S25 rows keep NULL chain columns, and a verifier starts at
   the first chained row rather than reporting a gap that never existed.
2. Watch the new replicas pass readiness (`/health`).
3. Roll the old ones out. The contract phase — dropping the pre-S25 compatibility — is a
   **later** release's job, once nothing runs the old code.

The upgrade-on-a-populated-database case is a test, not advice:
`tests/integration/test_resilience.py::test_the_release_migration_applies_to_a_populated_database`
runs a scan, rolls the schema back, upgrades again and asserts the rows are intact.

### 35.3 Autoscaling the scan farm

Workers are stateless, so they scale on queue depth (`arachne_queue_depth`) — and down to zero
when the estate is quiet:

```yaml
autoscaling:
  keda:
    enabled: true          # requires the KEDA operator (see the chart's NOTES)
  minReplicas: 0           # scale-to-zero
  maxReplicas: 8
  queueDepthPerReplica: 4  # how many queued scans one worker is sized for
```

The chart ships a KEDA `ScaledObject` *and* a plain HPA (never both — KEDA supersedes it). KEDA
is the recommended path because plain Kubernetes HPA cannot scale to zero and needs a
Prometheus adapter for an external metric. `arachne dr status --depth N` prints the same
decision the autoscaler makes, for an estate with no cluster at all:

```
scan farm:   3 replica(s) — queue depth 9 ÷ 4 per worker = 3
```

A scale-to-zero decision waits out a cooldown, so a burst arriving between two scrapes does not
make the farm thrash.

**The metric, precisely.** The scaler reads `arachne_queue_depth{status="queued"}` — scans
admitted and not yet leased, read from the database at scrape time so every worker reports the
same number. The family's other three series (`leased`, `done`, `cancelled`) are for the
dashboard, not for the scaler; the fleet's live work is carried unlabelled by
`arachne_queue_leases`.

**The starting threshold.** `queueDepthPerReplica: 4` means one worker per four queued scans.
It is a starting point, not a measurement: size it from the published throughput
(`benchmarks/envelope/envelope.json`, checks per minute per agent) against the arrival rate you
actually see. Two ways to get it wrong:

* **Too low** (1–2) makes the pool chase every burst, and the scale-down cooldown then removes
  capacity the queue still needs.
* **Too high** lets a backlog sit on too few workers, which shows up as a rising
  `arachne_queue_oldest_age_seconds` while the replica count stays flat.

The plain-HPA path needs a Prometheus adapter to publish the metric to the external-metrics API
(the chart does not install one). A rule for a cluster already running `prometheus-adapter`:

```yaml
rules:
  external:
    - seriesQuery: 'arachne_queue_depth'
      resources:
        overrides:
          namespace: {resource: "namespace"}
      name:
        matches: "^arachne_(.*)"
        as: "arachne_$1"
      metricsQuery: 'sum(<<.Series>>{<<.LabelMatchers>>,status="queued"})'
```

KEDA needs no adapter: its Prometheus scaler queries the API's `/metrics` directly.

### 35.4 Upgrade safety: the dry run, the declaration, and the destructive gate (WP-18, REQ-OPS-008)

Three things happen before a migration touches a database you care about.

**1. Read the SQL first.** `--dry-run` prints exactly what would run and changes nothing:

```bash
arachne db upgrade --dry-run                 # the plan, then the SQL
arachne db upgrade --dry-run --json          # the plan as JSON, for a review or a pipeline
```

Two renderings, named in the output rather than left to trust. On SQLite the statements are
captured by applying the upgrade to a **throwaway snapshot** of the database (SQLite's own
backup API, opened read-only) — the only way to render `batch_alter_table`, and the database
itself is never opened for writing. On other dialects Alembic renders them offline in `--sql`
mode, executing nothing at all. The command says which one it used, and why.

**2. Every migration declares whether it is reversible.** The declaration is a line in the
migration's own docstring (`reversible: true`), so it sits in the prose a reviewer already
reads:

```bash
arachne db migrations            # revision, file, reversible — one line each
arachne db migrations --check    # exit 1 if any migration declares nothing
```

The declaration is a *claim about the downgrade*, and `tests/unit/test_migrations.py` tests it
per revision: upgrade to it, downgrade to its parent, and compare the schema with a fresh
upgrade to that parent. At this release all 17 migrations measure reversible. A declaration
that flatters a migration fails in CI rather than during a rollback — the only moment a
downgrade ever matters.

**3. A migration that does not declare itself reversible needs an acknowledgement.**

```bash
arachne db upgrade                       # refused, naming the revision and its file
arachne db upgrade --allow-destructive   # proceed, having read the dry run
```

An *absent* declaration counts as non-reversible: the safe default is to ask. The refusal
happens before anything connects, so a mistyped upgrade cannot half-apply on a hunch.

**The populated-database case** is a test, not advice:
`tests/unit/test_migrations.py::test_an_upgrade_from_two_versions_back_succeeds_on_a_populated_database`
writes an estate through the ORM, rolls the schema back two revisions, upgrades again, and
asserts every table's row count and the data are intact.

## 36. Disaster recovery (S25, REQ-RESIL-005)

### 36.1 The objectives

| Objective | Shipped default | Where it is recorded |
|---|---|---|
| **RPO** — how much work a restore may lose | 24 h | `--rpo-seconds` on `arachne dr backup` |
| **RTO** — how long a restore may take | 1 h | `--rto-seconds`, and re-measured by `restore` |

The numbers are properties of the *procedure*, not of the code, so the bundle records what the
chosen cadence supports and `dr restore` prints what it actually took. A deployment whose
contract promises more runs `dr backup` more often and says so in its deployment record.

### 36.2 Taking a backup

```bash
arachne dr backup --out /backup/arachne-$(date +%F) \
    --key /etc/arachne/vault.enc --key /etc/arachne/secrets.manifest \
    --rpo-seconds 3600 --rto-seconds 900
```

The bundle holds:

| Path | Content |
|---|---|
| `database.json` | every table the schema owns (targets, scans, findings, evidence rows, the audit chain, …) |
| `evidence/` | the content-addressed object tree (each object verified against its own name) |
| `keys/` | the sidecars you named — already encrypted (the credential vault, the secrets manifest) |
| `config.json` | the deployment's non-secret settings, secrets replaced by `{"set": true}` |
| `manifest.json` | counts, artifact digests, region, schema revision, RPO/RTO, and the signature |

Two things it deliberately does **not** do:

- **It does not copy an S3-backed evidence store.** The object store's own lifecycle and
  replication are the right mechanism; a half-copied bucket would be worse than a documented
  pointer. The bundle records the object keys and says so in its notes.
- **It does not hold your integrity key.** The manifest records the key *id* so a restore can
  tell which key signed the bundle; the key itself stays in your secret store. Keep it there —
  without it the trail's signatures cannot be verified, so back the key up out of band too.

Write the bundle to a fresh directory — a backup that mixes with an older one is not a snapshot
of anything — then get it off the host.

### 36.3 Restoring

```bash
# Rebuild the instance: fresh database, schema at or ahead of the bundle's revision.
arachne db upgrade

# Verify and load (refuses a target that already holds the bundle's scans).
arachne dr restore /backup/arachne-2026-10-31 \
    --evidence-dir /var/lib/arachne/evidence --keys-to /etc/arachne
```

The bundle is verified before it is used: every artifact's digest, every table's row count and
the manifest's signature. A tampered, truncated or unsigned bundle is refused and **nothing is
restored**. Rows are inserted one table at a time in foreign-key order, so a partial restore is
never committed.

After the restore:

```bash
arachne verify-chain            # the trail should verify end to end
arachne scan --dry-run ...      # a smoke scan against a lab target
```

### 36.4 A rehearsal schedule (do this; do not assume)

| Cadence | Act |
|---|---|
| Nightly | `arachne dr backup`; move it off-host; keep the last 30 |
| Weekly | verify a bundle by restoring it onto a scratch instance |
| Monthly | full restore rehearsal on an isolated instance; record the measured RTO |
| Per release | re-run the rehearsal; re-check `head_migration.expand_only` |

### 36.5 The rehearsal, unattended (WP-18, REQ-OPS-010)

The schedule above is advice. `arachne dr rehearse` is the mechanical version of it, and the
one a scheduled job runs:

```bash
arachne dr rehearse --record var/dr/rehearsals.jsonl
arachne dr rehearse --json --record var/dr/rehearsals.jsonl
arachne dr rehearse --history --record var/dr/rehearsals.jsonl   # the trend
```

Five stages, each named and timed, because "the rehearsal failed" is not actionable at 3 a.m.:

| Stage | What it proves |
|---|---|
| `backup` | a full, signed bundle can be written from the source database |
| `restore` | the bundle loads into a **scratch** database the rehearsal created |
| `row-counts` | every table's restored count equals the count its manifest declares |
| `audit-chain` | the restored copy's chain, anchors and row signatures verify (INV-8) |
| `objectives` | the measured RTO and RPO are inside the declared objectives |

The source database is only ever read; the scratch database and the bundle are removed at the
end (keep them with `--keep-scratch`). Nothing needs a cluster: the scratch database is a fresh
SQLite file, so the rehearsal runs on a laptop, in CI, and in a staging namespace alike.

**The two measured numbers**, defined precisely because a vague RTO is one nobody can falsify:

* **measured RTO** — wall-clock from the start of the rehearsal to the end of verification:
  how long until the deployment could serve again with a state it trusts.
* **measured RPO** — the age, at the moment the backup began, of the newest row the source
  holds: how far back the recovery point takes you, and therefore what a restore would lose.

**It fails loudly.** A broken stage prints the stage's name and exits non-zero; nothing is
reported as a pass on the strength of the stages before it. A run that restores correctly but
exceeds an objective also fails — recovering, but too slowly, is a failed rehearsal, not a pass
with a note. Every run appends one JSON line (pass or fail) to the record file, so "we rehearse
monthly" is a file of measurements rather than a claim.

**On a schedule.** `.github/workflows/rehearsal.yml` runs it nightly in CI — a non-production
environment with a populated SQLite database — and uploads the record as an artefact. Point it
at staging instead with `--database-url` and an `ARACHNE_INTEGRITY_KEY`, and the rehearsal will
exercise the signature check too (without a key it says so in its notes rather than pretending
it did).

## 37. Verifying the trail: `arachne verify-chain` (S25, REQ-TRUST-005)

```bash
arachne verify-chain                        # verdict; exit 1 when not intact
arachne verify-chain --json                 # the full report, for a monitoring system
arachne verify-chain --scan 42              # one scan's rows and seal
arachne verify-chain --require-signatures   # treat "unsigned" as a failure
```

It checks five things:

1. **The audit hash chain.** Every chained event's `hash` is recomputed from its content and
   position. An edit changes it (`modified`); a missing row leaves a gap in `seq` *and* a
   dangling `prev_hash` (`deleted` / `reordered`). Those are separate findings on purpose:
   "modified" and "missing" are different answers to an auditor.
2. **The anchors.** Each signed checkpoint must be reachable by the log. A log that no longer
   reaches its last anchor has had its **tail deleted** — the one failure a chain cannot see on
   its own.
3. **Row signatures.** Every finding's and evidence row's deployment-key signature is
   re-verified, including the evidence payload's digest.
4. **Evidence content hashes.** Every stored evidence blob's hash is recorded in the chain when
   it is captured (WP-14, REQ-PROOF-018), and the recomputed digest of the stored payload is
   compared with that record — so an edit behind the store's back is found even on a deployment
   that configured no key. The verdict is `[evidence.mismatch]` and it names the evidence id;
   a recorded blob whose row is gone while its scan survives is `[evidence.deleted]`. Evidence
   whose whole scan was pruned by retention is reported as a **note**, not a finding: policy,
   not tampering. (A re-mask under §39 records the blob's new hash, so the chain's latest
   statement stays true.)
5. **Scan seals.** Each completed scan's signed manifest is recomputed. A row that is gone is a
   deletion, a row that appeared is an insertion, a row whose content changed is an edit — and
   the report names it.

```
verify-chain: intact (105 audit_rows, 8 findings, 21 evidences, 1 seals, 29 sealed_rows, 21 evidence_hashes)
```

Issues print as `[<check>.<kind>] <subject>: <detail>`, so `[evidence.mismatch] evidence:21:
… the blob was edited after capture` names both what was checked and which row.

Exit codes: `0` intact, `1` not intact (issues on stderr), `2` the command could not run (no key
when `--require-signatures` was given). Every run is itself audited (`integrity.verified` or
`integrity.tamper`).

### 37.1 Verifying without the power to forge: Ed25519 (WP-19, REQ-TRUST-008)

An HMAC deployment key means the verifier holds the signing key. If a third party — an auditor,
a customer, a regulator — must be able to check the chain, that is exactly the property they
must not have: they could fabricate a row and its signature. The asymmetric option fixes it.

**On the host that signs** (generate a pair first; keep the seed like any other secret):

```bash
python -c "from arachne.core.signing import generate_keypair; print(*generate_keypair(), sep='\n')"
export ARACHNE_INTEGRITY_ALGORITHM=ed25519
export ARACHNE_INTEGRITY_ED25519_KEY_FILE=/run/secrets/arachne-integrity-ed25519-seed
export ARACHNE_INTEGRITY_ED25519_PUBLIC_KEY=<the 64-hex public half>   # optional: cross-checked
```

**On the auditor's machine** (the public key only — this deployment verifies and refuses to
sign, which is the point):

```bash
export ARACHNE_INTEGRITY_ALGORITHM=ed25519
export ARACHNE_INTEGRITY_ED25519_PUBLIC_KEY=<the public half>
arachne verify-chain --require-signatures
```

What the auditor can and cannot do is worth stating plainly: they can confirm that every link,
anchor, row signature and seal was produced by the holder of the seed, and they cannot produce
one (`Ed25519Signer.sign` refuses on a public-key-only instance, and nothing derives a seed from
a public key). Signatures read `<scheme>:<key id>:<hex>` — `ed25519:` for this scheme, `v1:` for
the historical HMAC tag (still minted, so upgrading a reader does not invalidate a stored row).
The key id is a digest prefix of the public key, so an auditor can name the key whose absence
would explain a refusal.

**The dual period.** Migrating is not a flag day: set `ARACHNE_INTEGRITY_ALGORITHM=ed25519`
*and keep* `ARACHNE_INTEGRITY_KEY`. New rows sign with Ed25519 while `verify-chain` keeps
verifying with both keys, so every row and anchor written before the switch still passes. Drop
the HMAC key once your retention window has passed the last pre-switch row; `verify-chain
--require-signatures` will tell you if you were early.

Two operational notes. The Ed25519 implementation is pure Python and **not constant-time**
(`docs/adr/370-trust-hardening-and-purple-breadth.md`): keep the seed off hosts you do not trust
against a local timing attacker. And a public-key-only deployment writes **unsigned** seals and
anchors — it is a verifier, not a signer — so it should never be the process that finishes
scans.

## 38. Evidence residency (S25, REQ-RESIL-004)

A tenant's contract can require that its evidence never leaves a region — and "never" has to be
enforced, not documented.

```bash
export ARACHNE_REGION=eu-west-1                              # this deployment's region
arachne project residency --project acme --region eu-west-1  # pin a tenant
arachne project residency --project acme --clear             # unpin
```

Every evidence row written is stamped with the deployment's region. A read or a presigned URL
for a row pinned to a region this deployment does not serve is refused with the same 403-family
error a scope refusal uses (`residency.rejected` in the trail, with both regions named) — for
inline payloads as well as offloaded ones, because a boundary that only covers the large
payloads is not a boundary.

Both values must be set for the check to bite: no `ARACHNE_REGION` (or no pin on the project)
means "not pinned", which is the pre-S25 behaviour. **A multi-region estate runs one ARACHNE
deployment per region**, each with its own region set and its own store — that is what makes
the stamp meaningful.

## 39. PII in captured evidence (S25, REQ-TRUST-006)

Evidence is a copy of what the target served, so it can contain personal data. A project's
policy decides what happens to it, and the masking happens **at capture** — before the payload
reaches the database, an object store, a report, a log line or the audit trail.

```bash
# Deployment default (a project's own policy overrides it wholesale).
export ARACHNE_PII_ENABLED=true
export ARACHNE_PII_CATEGORIES=email,phone,ssn,credit-card,iban,ipv4
export ARACHNE_PII_ACTION=mask            # mask | hash | drop
export ARACHNE_PII_SALT=<random>          # required when action=hash
export ARACHNE_PII_RETENTION_DAYS=90      # re-mask evidence older than this in the prune run

# Per project.
arachne project pii --project acme --enable --categories email,ssn --action hash
arachne project pii --project acme --clear
```

| Action | Result |
|---|---|
| `mask` | `[PII:email]` — the category is kept, the value is not |
| `hash` | `[PII:email:9f86d08188]` — a salted pseudonym: two occurrences stay correlatable, the value is not recoverable |
| `drop` | the value is removed entirely |

Detection is deliberately conservative, with the validators that make a pattern trustworthy:
Luhn for a card number, mod-97 for an IBAN, SSN area rules, an octet-range check for an IPv4,
and "the national phone form must be grouped and consistently punctuated". A sixteen-digit
version string, an ISO timestamp or a checksum is *not* PII and is left alone — a report has to
stay readable.

`ARACHNE_PII_RETENTION_DAYS` is the REQ-DATA-001 hook: evidence older than that is re-masked by
the retention pruner, which is the mechanism for "we decided to mask later than we started
scanning". Both paths audit **counts by category** (`pii.masked` at capture, `pii.remasked` in
the prune run), never a value.

**The retention re-mask, precisely** (WP-14, REQ-DATA-005):

* `ARACHNE_PII_RETENTION_DAYS=0` — the default — means **mask at capture only, never re-mask**.
  A deployment that has not asked for the pass has none of its stored payloads rewritten.
* `arachne retention plan` (or `retention prune` without `--apply`) **changes nothing**: it
  reports how many blobs the window covers and how many occurrences it found per category.
  `arachne retention prune --apply` performs it.
* An **inline** payload is masked in place, under the *project's* policy (`projects.pii_json`,
  else `ARACHNE_PII_*`), and one audit event per masked blob (`pii.remasked`) records the
  categories, the counts and the blob's new content hash — never a value.
* An **offloaded** payload (one whose bytes live in an evidence backend) is **not** re-masked
  by this pass and is **reported as such**: `pii.remask_unsupported` names the reason and a
  bounded sample of the blob ids, and the plan carries the same count. It is never skipped
  silently — that is the difference between a control that is partial and one that lies.
* A project on **legal hold** is not re-masked either: an operator who suspended retention has
  not asked for stored evidence to be rewritten.
* Re-masking changes a payload the integrity layer already described, so the affected rows are
  re-signed and their scans re-sealed (`integrity.sealed` with reason `pii-remask`), and the
  new content hash is recorded in the audit chain. `arachne verify-chain` therefore stays green
  after a re-mask: the privacy control and the tamper-evidence control agree rather than
  contradicting each other.

Masking is irreversible on purpose. A deployment that could un-mask would have kept the value,
and the point is not to keep it.

## 40. External validation artifacts (S25, REQ-TRUST-007)

ARACHNE ships its own disclosure and validation paperwork, and the deployment serves it:

| Artifact | Path | Reachable at |
|---|---|---|
| Vulnerability disclosure policy | `SECURITY.md` | the repository |
| `security.txt` (RFC 9116) | `docs/security.txt` | `/.well-known/security.txt` |
| External pentest report (methodology + placeholder register) | `docs/external-pentest-report.md` | the repository |

`/.well-known/security.txt` is served unauthenticated, like `/health` — the file exists for
someone *outside* the deployment — and it is read from the repository, so what is published is
what was reviewed. The pentest report is an explicit placeholder until the first commissioned
test: it states its scope, methodology and severity/remediation scheme, and its findings
register is empty because no test has run. Absence of findings is not a security claim, and the
document says so.

## 41. Content packs, the marketplace and the review pipeline (S26, REQ-ECOS-001)

S25 (§34) made a content pack the unit of *transport* into an air-gapped estate: signed, and
verified on import. S26 adds the unit of *trust*: a third party's pack is reviewed before this
deployment will list it, and `arachne packs import` refuses a pack that has not passed.

### 41.1 The three gates

`arachne plugin review <pack>` runs three independent gates over the pack and prints one report.
They are independent on purpose — they fail for different reasons, and the operator action
differs:

| Gate | What it checks | A pass means |
|---|---|---|
| `signature` | the pack's signature verifies against **this** deployment's content key (`ARACHNE_INTEGRITY_KEY`), and — if this deployment names trusted key ids — against one of those | the pack came from someone this deployment trusts, and its manifest was not edited |
| `safety` | every `.py` member is parsed and walked (AST) for constructs a detection plugin may not use; every declared check YAML is checked for proof-ladder consistency | the pack does not reach outside the plugin API, and no declared check would run on an authorization that never covered it |
| `parity` | the declared `meta.kind` and `meta.entry_point_group` agree and are platform-owned; declared check ids and report-format names do not collide with the built-ins | the pack **adds** a check/format, it does not silently **replace** one |

A pack is `listed` only when **all three** pass — there is no partial listing. A pack that does
not even parse (not a tar.gz, a corrupt archive) comes back as a *rejection report*, not an
exception, because "this pack is hostile" is an outcome to record while "this is not a pack" is
a usage error.

```bash
arachne plugin review third-party-2026.10.tar.gz            # review; prints each gate's reason
arachne plugin review third-party-2026.10.tar.gz --json     # the full report, for CI
arachne plugin review third-party-2026.10.tar.gz --publish  # record the verdict (provenance)
```

`--publish` records the verdict in `pack_reviews` (migration 0012) and audits it
(`pack.reviewed`). The verdict is bound to the pack's **digest**: rebuilding the pack with
different content does not inherit the old verdict, because a review is evidence about bytes,
not about a name. Exit code is `0` for `listed` and **`2` for a rejection**, so a CI job can
gate on it.

### 41.2 What the safety gate blocks — and what it is not

The scan is on the AST, not the text: it sees `__import__("subprocess")`, and it does not flag
the word in a docstring. Blocking findings:

- **imports** of `subprocess`, `multiprocessing`, `ctypes`, `pty`, `socket`, `telnetlib`,
  `ftplib`, `smtplib`, `imaplib`, `poplib`, `pickle`, `marshal`, `shelve`, `dbm`,
  `http.client`, `urllib.request`, `urllib.error`, `requests`, `urllib3`, `aiohttp`, `httpx`,
  `paramiko`, `asyncio.subprocess`;
- **calls** whose dotted name starts with `subprocess.`, `multiprocessing.`, `ctypes.`,
  `pickle.load*`, `marshal.load*`, `os.remove`/`unlink`/`rmdir`/`removedirs`/`chmod`/`chown`/
  `setuid`/`setgid`, `shutil.rmtree`/`move`, `signal.`, `runpy.`, or whose **last component** is
  `popen`, `system`, `spawn*`, `exec*`;
- **bare** `eval`, `exec`, `compile`, `__import__`;
- a **syntax error** in any member ("we could not parse it" must not look like "we found
  nothing").

Non-blocking warnings: `open`/`input`/`breakpoint`, a write-looking file call, and a mutation of
`sys.modules`/`sys.path`/`os.environ`.

The **proof-ladder consistency** check is on the declared content, not the Python: a check that
declares `proof: L3` or `L4` (it changes state on a target) without
`requires_state_attestation: true` is refused, because it would otherwise be planned and run on
an authorization that never covered a state change.

> **This is a policy gate, not a sandbox.** The pack still runs in-process after it is listed.
> The gate makes an honest mistake loud and raises the cost of shipping a hostile pack; it does
> not confine a determined one. `docs/security-review.md` §18 states this plainly.

### 41.3 Listing, importing, and the fail-closed load boundary

```bash
arachne plugin marketplace                 # each entry annotated review=listed|rejected|unreviewed
arachne packs import third-party-2026.10.tar.gz   # refuses a pack with no listed review
arachne packs list                         # what this estate is running
```

`arachne plugin marketplace` shows a review status per entry. `unreviewed` is honest, not an
error: the marketplace is an inventory, and the review flag is an annotation on it (a deployment
with no provenance store degrades to `unreviewed` rather than making the catalogue unreadable).

With `ARACHNE_PLUGIN_REQUIRE_REVIEW` **on (the default)**, `arachne packs import` refuses a pack
that has no *listed* review recorded for its exact digest. The escape hatch is
`ARACHNE_PLUGIN_REQUIRE_REVIEW=false` or `ARACHNE_PLUGIN_ALLOW_UNSIGNED=true`; both are recorded
in the audit trail. The same posture S25 set — importing is the act that *trusts*, so it is the
act that demands a review and a signature.

### 41.4 Configuration reference (S26, review)

| Variable | Meaning | Default |
|---|---|---|
| `ARACHNE_PLUGIN_REQUIRE_REVIEW` | refuse a pack with no *listed* review for its digest | `true` |
| `ARACHNE_PLUGIN_ALLOW_UNSIGNED` | accept an unsigned pack in review (a lab only) | `false` |

The API is `GET /api/v1/plugins/reviews`, `POST /api/v1/plugins/review` (admin; `pack` is a
**host path**, not an upload — the file must be on the server), and `GET
/api/v1/plugins/marketplace`, which is the annotated listing.

## 42. The product UI: attack-path graph, executive dashboard and golden snapshots (S26, REQ-ECOS-004)

S26 adds the two pages an executive and a tenant actually use, and makes the tenant quality page
self-service. Everything is rendered by the API process — no separate frontend, no build step.

### 42.1 The pages

| Page | What it shows |
|---|---|
| `GET /ui/posture` | the executive dashboard: posture trend, drift periods, the fix-verification loop, the estate inventory, watched scopes, and control coverage |
| `GET /ui/scans/{id}/attack-paths` | the attack-path graph for one scan |
| `/ui/quality` | now tenant **self-service**: suppressions and risk acceptances, scoped to the selected project |

The posture page's control coverage comes from the **newest scan and is labelled with its id** —
not averaged across scans, because coverage is a statement about which checks ran, and an
average would state something else. The quality page is scoped to the selected project; `?scope=all`
is the MSSP operator's deployment-wide audit view, and `?all_projects=true` is the API
equivalent.

### 42.2 The visualizations are server-rendered SVG, and the goldens are those bytes

The charts are written by hand as deterministic SVG in `src/arachne/api/ui_visuals.py` — no
browser, no JavaScript build:

- `attack_path_svg` — one row per composed chain, kill-chain stages left to right; a **filled**
  node is a verified hop, a **hollow** node is a candidate and names the check that would verify
  it, and a thick ring marks the cheapest break.
- `posture_trend_svg` — stacked severity bars per scan; a **clean** scan gets a baseline tick so
  "scanned and found nothing" is not drawn as "did not scan".
- `coverage_bars_svg` — pass/fail/gap bands plus a hatched **unmapped** remainder, because a
  framework's unaddressed controls are the point of the chart.

Every label is HTML-escaped, because an asset value is target-controlled.

**The golden files are not browser screenshots.** The suite has **no headless browser**, and that
is a deliberate choice: a pixel comparison would add an installation dependency and a flake
source, and the value of the test is the diff, not a rasterized image. The visualization **SVG is
the screenshot** — a deterministic, diffable, reviewable-in-a-pull-request document — and the
pages that carry them are HTML snapshots. `tests/report_qa/golden/` holds them:

| File | Pins |
|---|---|
| `attack-path-graph.svg` / `posture-trend.svg` / `control-coverage.svg` | the three visualizations (REQ-ECOS-004) |
| `ui-posture-page.html` / `ui-attack-paths-page.html` / `ui-quality-page.html` | the three pages, normalized |
| `report-en.md` / `report-fr.md` / `report-mspp-fr.md` | the report labels in each locale (REQ-ECOS-005/006, §43) |

Re-bless after an intended change:

```bash
ARACHNE_GOLDEN_UPDATE=1 pytest tests/report_qa/test_ecos_golden.py tests/integration/test_ui_ecos.py
```

The blessed run **fails on purpose**, so a blessing never passes silently in CI; re-run without
the variable and review the diff before committing it. The HTML normalizer collapses exactly two
volatile tokens (the render timestamp and the operator label) and nothing else.

### 42.3 Tenant self-service is scoped by the request, never the form

`suppressions.project_id` and `risk_acceptances.project_id` are nullable (migration 0012). A
**NULL** row is **deployment-wide** — every row written before S26 keeps NULL and therefore stays
visible to every tenant, which is exactly why the migration changes no existing behaviour. The
store takes `project_id`/`include_global`; the tenant always comes from the **request**
(header/cookie), never from the form body, so a user cannot forge which tenant's rules they are
editing.

## 43. Report language and white-label/MSSP mode (S26, REQ-ECOS-005/006)

### 43.1 The report can be delivered in a second language

The report's **structural labels** are translatable: the 12 numbered section headings, the 9
appendix sub-headings, the severity names, the per-finding labels, the cover labels and the
attack-path table headers. The catalogue is `src/arachne/templates/i18n/fr.yaml`, a sibling of
`en.yaml` with the **same key set** — a test fails the build if the two diverge, because a
missing key would fall back to English silently.

Selection is per report, and precedence runs from the most specific to the deployment default:

1. `arachne report --scan 12 --locale fr`
2. `GET /api/v1/scans/12/report?locale=fr`
3. the project's stored default — `arachne project locale --project acme --locale fr` (or
   `--clear` to inherit again); `POST /api/v1/projects` accepts `report_locale` too. The store
   validates it as a language tag, so a value that is not one fails loudly rather than silently
   falling back
4. the deployment default `ARACHNE_REPORT_LOCALE`

An **unknown locale falls back to English rather than failing**: a report that refuses to render
because of a language tag is worse than one in English. Identifiers are never translated (check
ids, CWE/CVE/CVSS values, asset names), and the executive-summary counts table is deliberately
not translated — its rows come from the canonical `SeverityCounts.as_rows()` vocabulary the
machinery matches on.

> **Scope of this release.** The *narrative prose* — the executive-summary paragraphs and the
> explanatory sentence under each section — still ships in **English**. It is catalogue-able (a
> translation pass, not a renderer change), but it is not translated in this release. The report
> schema is **1.10** (a top-level `locale`).

### 43.2 White-label / MSSP mode

An MSSP delivers the same scanner's output under its own name.
`report.branding.resolve_branding(settings, override)` is the **single resolver** the CLI, the
API and the builder all use: deployment default ⊕ per-tenant branding ⊕ white-label mode.

```bash
export ARACHNE_REPORT_WHITE_LABEL=true        # a *deployment* setting
arachne report --scan 12 --project acme --format html
```

In white-label mode the product name falls back to the tenant's company name (unless the tenant
names its own product) and the ARACHNE attribution is forced off. Because it is a **deployment**
setting, a tenant cannot switch it back on — that is what makes "our MSSP delivers under our
name" a property of the deployed product rather than a per-tenant suggestion. Existing per-tenant
branding (`projects.branding_json`) is unchanged, and `Branding` gained no field: white-label is
a mode applied to the existing data.

### 43.3 Configuration reference (S26, language & branding)

| Variable | Meaning | Default |
|---|---|---|
| `ARACHNE_REPORT_LOCALE` | deployment default report language (a BCP-47 tag such as `fr`) | *(empty = English)* |
| `ARACHNE_REPORT_WHITE_LABEL` | force white-label/MSSP presentation deployment-wide | `false` |

## 44. Generated API clients: Python and TypeScript (S26, REQ-ECOS-002)

The REST API ships with generated clients, so a consumer does not hand-write an HTTP client
against a moving API. `python -m arachne.tools.sdkgen` writes `clients/python/arachne_client/`
and `clients/typescript/src/` from the **running application's** OpenAPI document
(`create_app().openapi()`), never from a checked-in file, so the clients cannot describe an API
the process does not serve.

```bash
python -m arachne.tools.sdkgen            # regenerate the clients
python -m arachne.tools.sdkgen --check    # CI drift gate: exit 1 and name any file that differs
```

The clients are **committed**, so a consumer can read them without running the generator, and CI
enforces that they match the spec.

Two properties are structural and tested:

- **Auth cannot be skipped.** Both clients require a non-empty API key at construction, and every
  request goes through **one** chokepoint that sets the `x-api-key` header (and `x-project` when
  a tenant is selected). There is no per-method path around it.
- **A rate limit is never retried blindly.** A `429` is surfaced as a typed error that honours
  the server's `Retry-After`; the client does not wait the limit out and re-send.

The contract tests are the proof: the generated **Python** client runs against a real server
(`tests/integration/test_sdk_contract.py`) and the generated **TypeScript** client runs live
under `node` with native type stripping, both asserting 401-without-a-key, the happy path, and
429-under-burst. The node test **skips cleanly** when `node` is not on `PATH`, and the skip is
asserted rather than assumed.

> **Honest limitation.** The generated *types* cover the spec partially. A free-form object, an
> array without `items`, a non-string enum, or a `$ref` outside `components.schemas` becomes a
> generic JSON type, marked in-source with `# generic JSON:` / `// generic JSON:` so a reader sees
> where the type is a placeholder. Nothing is silently mistyped; some things are honestly typed
> as "any JSON".

## 45. CI integrations (S26, REQ-ECOS-003)

S26 adds the delivery surfaces that put the pre-deploy gate's findings where a reviewer reads
them: a GitHub composite Action, a GitLab CI component, a Terraform module wrapping the Helm
chart, and a Terraform provider **skeleton**. The full reference — the gate's exit policy, the
`python -m arachne.tools.ci_annotate` tool and its flags, and the workflow/component snippets —
is [`docs/ci-integration.md`](ci-integration.md); do not duplicate it here.

Two things to know when you wire it in:

- The gate is the pre-deploy review that already existed (S23, REQ-POSTURE-002): it scans a local
  tree with the real M5 checks and exits `0` clean / `1` below the threshold / `2` at-or-above.
  It is **offline by construction** — the target is a `repo:` reference, no clone or fetch.
- A scan writes to the control-plane database, so a job needs a schema first
  (`ARACHNE_DATABASE_URL` plus `arachne db upgrade`); a job-local SQLite file is enough. This
  repository's own CI job runs the gate on `tests/fixtures/iac/misconfigured` and asserts exit 2.

The Terraform provider under `deploy/terraform/provider/` is an explicit **skeleton**: it is not
functional, not published, and manages nothing. It exists to fix the eventual provider's shape
next to the real module.

## 46. Remediation as code (S27, area FIX)

Area FIX closes the loop all the way round: instead of stopping at "here is what is wrong", the
engine proposes **the fix as a reviewable artifact** — a patch diff for a repository the operator
granted, or an IaC/cloud configuration change for a local tree. The invariant is in the name of
the section: *ARACHNE proposes, a human decides, ARACHNE verifies.*

**Auto-merge and auto-apply do not exist in this program.** There is no verb, flag or
configuration that merges a branch, applies a patch, or pushes to a default branch — not as a
default that can be turned on, but as code that was never written: the one module that runs git
has a closed subcommand vocabulary (``worktree``/``add``/``commit``/``branch`` and read-only
queries) and `tests/test_fix_safety.py` asserts that no other verb — ``push``, ``merge``,
``reset``, ``fetch``, ``clone``, ``checkout`` … — can appear in it.

### 46.1 What a proposal is, and what it never does

`arachne fix propose <finding-id>` builds, records and *does not apply* a proposal:

```bash
arachne fix propose 42 --by jane.operator@example.com   # a diff in the database, nothing else
arachne fix show 1                                      # the artifact, its verdicts and its trail
```

The proposal carries the plan it used, the author (`template`), the diff, the files it touches,
a scope verdict, the IaC self-scan verdict, the repository's own test result and the whole
audit trail from the finding to the proposal. Nothing outside ARACHNE changes at this point: the
repository is untouched, and no process is started.

Two settings matter here, and they are the whole authorization model:

```bash
ARACHNE_FIX_GRANTS=/etc/arachne/fix-repos.yaml   # who may be fixed. Unset ⇒ nobody.
ARACHNE_FIX_PLANS=/etc/arachne/fix-plans.yaml    # optional: your own plan catalog
ARACHNE_FIX_ARTIFACTS_DIR=/var/lib/arachne/fix   # optional: where PR artifacts are written
```

There is **no bundled default grant file**: an authorization that ships with the tool would be an
authorization the operator never gave. With no grants, a repo-class finding produces a recorded
refusal plus the remediation catalog's steps — never a diff. `arachne fix repos` shows what is
authorized; `arachne fix plans` shows which classes ARACHNE can turn into an artifact.

### 46.2 Authorizing a repository (the grant file)

```yaml
# /etc/arachne/fix-repos.yaml
version: "1.0"
repos:
  - name: payments-api
    path: /srv/git/payments-api          # a LOCAL tree: ARACHNE never clones
    default_branch: main                 # the one branch it must never touch
    test_command: [python3, -m, pytest, -q, specs]   # the repo's OWN suite
    test_timeout_seconds: 900
    max_files: 12
    max_changed_lines: 400
    allow_untestable: false              # a risk acceptance, per repo, off by default
    baseline_test_run: true              # run the suite on the base commit first
```

What each field buys, in the order the engine uses them:

- **`path`** — resolved once, at authorization time. Every later comparison is on resolved paths,
  so a symlink cannot retarget a grant between the proposal and the submission. A remote
  reference (`git@…`, `https://…`) is refused at load time: there is nothing to authorize
  remotely, because ARACHNE does not fetch.
- **`test_command`** — the repository's own suite, as an argv list. ARACHNE **never invents a
  command**: an empty `test_command` marks the repo untestable, and untestable proposals are
  flagged. The program has to be on a short, shipped runner allowlist (`pytest`, `python`,
  `python3`, `tox`, `nox`, `npm`, `pnpm`, `yarn`, `make`, `go`, `cargo`, `mvn`, `gradle`) — that
  list is the honest answer to "which programs can a grant make this deployment execute", and
  adding one is a code change a reviewer sees. Arguments may not contain shell metacharacters;
  nothing is ever passed to a shell.
- **`default_branch`** — the branch a fix is forbidden to touch. It is re-read before and after a
  submission and a change is a hard error, not a warning.
- **`baseline_test_run`** — runs the suite on the base commit first, so "the tests pass" can never
  be claimed for a repository whose suite was already red. That case is flagged
  (`baseline-failing`) and nothing is created.

### 46.3 The PR workflow (REQ-FIX-002)

```bash
arachne fix approve 1 --by jane.operator@example.com   # the human gate, and it names a human
arachne fix submit 1                                   # tests first, then the branch
```

A submission refuses to proceed without an approval that names someone. Then, in order:

1. the plan is re-applied and the fresh diff is compared with the approved one — a **stale**
   proposal is refused rather than committed, because the artifact a human approved must be the
   artifact submitted;
2. the repository's own test suite runs **in a throwaway worktree** of the base commit, first
   unpatched (baseline) and then patched. A failure is flagged (`tests-failed`), audited and
   never submitted — the risk-R-18 case, and the reason `arachne fix submit` can exit `1` having
   changed nothing;
3. only then is the dedicated branch created — `git branch arachne-fix-<finding>-<plan> <commit>`
   **in the authorized repository**, from a commit produced in a scratch worktree that is removed
   afterwards. The operator's checkout, its `HEAD` and its default branch are never switched,
   written or moved (and the record carries `default_branch_unchanged`);
4. with `ARACHNE_FIX_ARTIFACTS_DIR` set, the reviewable artifacts are written there: `patch.diff`
   (exactly what the branch changed) and `PR.md` (finding, plan, diff, scope verdict, self-scan
   verdict, test result, and the note that ARACHNE did not merge it).

Nothing is pushed anywhere. The "pull request" is the branch in the authorized repository plus
the artifact directory; opening a forge PR from it is the operator's act, with their credentials,
in their own tooling.

> **Operational note on correlation.** A plan is selected by the *artifact rule* a finding
> reports, and by default the analyzer correlates same-asset findings into one primary finding.
> For a repository target that means the first rule is the one a proposal can address
> (`analysis.correlation_enabled: false` gives one finding per rule, which is what this
> repository's own integration test uses). Either way the other findings stay visible as related
> evidence; the choice is recorded here so nobody has to discover it from a refusal.

### 46.4 Proving the artifact is scoped (REQ-FIX-003)

Every diff is judged before it may be stored, and each prohibition has a named test:

| What is refused | Why it can never be part of a fix |
|---|---|
| a diff that **adds** credential material | ARACHNE must not write secrets into a repository |
| a diff that **removes** a credential | the removed line would reproduce it — the diff is masked (and becomes manual) or refused |
| file deletion, mode change, symlink, rename, binary | a fix is a scoped text edit, not a restructure |
| a path outside the plan's own target list | "scoped" is a property of the artifact, not of the code path |
| any edition of a dependency manifest or lockfile | no dependency upgrade is ever part of a fix |
| an added line that deletes or overwrites state | a fix narrows exposure; it does not run destructive commands |
| more files or lines than the grant allows | the operator's numbers, not the engine's opinion |

Because a credential-removal diff cannot be both honest and secret-free, the shipped catalog
ships no such plan: that class comes back as guidance (the remediation catalog's steps) and the
fix-verification loop closes it after the operator's own edit.

### 46.5 IaC self-scan and the verification loop (REQ-FIX-004/005)

An IaC proposal is validated against **ARACHNE's own scanner** before it is recorded: the changed
files are reviewed twice — as the finding found them, and as the fix would leave them — and the
proposal is refused if the fix *introduces* a finding (a rule firing after that did not fire
before). The delta is the point: a file may already carry a second, unrelated misconfiguration,
and blaming the fix for it would only push the operator to widen the diff.

```bash
arachne fix applied 1 --by jane.operator@example.com   # the human says the fix landed
arachne fix verify 1                                   # targeted re-scan; auto-close on absence
```

`verify` runs the S23 fix-verification loop (section 32.5): a targeted re-scan of only the
affected checks against the same target. On verified absence the finding is **closed** and the
act is linked onto the proposal (`verification_id`, `verification_outcome`, the scan id); when
the check still reports, the proposal reads `still-open` and nothing is closed. That is the whole
of "propose → apply → auto-close".

### 46.6 AI-assisted authoring (REQ-FIX-006)

Off by default, and inert without an injected author: no prompt stage is shipped for patch
authoring, so the template engine authors every proposal and the record reads `parity: n/a`. A
deployment that wires its own second engine gets the parity gate: for a class a template covers,
the template's artifact is the artifact used, and the second engine's draft must agree with it
line for line — agreement is recorded (`parity: ok`), divergence is recorded and flagged
(`ai-parity-divergence`) and never substituted. A class no template covers may be authored by the
model only with `ARACHNE_FIX_AI_AUTHORING=1`, and its draft then faces exactly the same gates: the
scope analysis, the repository's own tests, and the self-scan.

## 47. Simulation & what-if modeling (S28, area SIM)

Area SIM answers the one question a scanner cannot answer by scanning: *"what if?"*. The estate
becomes a **model** — hosts, the services a scan observed answering, the identities a scan proved
reach, and the findings that sit on them — and hypothetical states (a new exposure, a compromised
credential, a newly published vulnerability, a proposed fix) are injected into a *copy* of that
model. The resulting attack paths are computed purely, and nothing is touched.

### 47.1 The invariant: the simulation engine cannot reach a target

This is not a convention or a configuration default; it is enforced in two independent ways, and
the difference matters when you are deciding whether to run it.

- **At the source (static).** The package `src/arachne/sim/` may not import the socket family, any
  HTTP client, `asyncio`, `subprocess`, or any ARACHNE module that owns an egress or a store path
  (`core.http`, `core.net`, `modules.*`, `creds`, `proof`, `data`, `api`, `scheduler`, ...). The
  rule is data, not prose: `arachne/sim/hygiene.py` declares it and scans for violations, and
  `tests/test_sim_safety.py` runs that scanner over the shipped tree — so a future edit that adds
  `import httpx` to a simulation file fails CI. Exactly one file is exempt, and only for one
  import: `sim/boundary.py` holds `socket` **in order to deny it**, and the exemption is pinned at
  that file and that import so nothing can quietly join it.
- **At runtime (fail closed).** Every public entry point (`build_estate_graph`, `simulate`,
  `simulate_change`, a re-simulation) runs inside
  `arachne.sim.boundary.no_network(...)`, which replaces `socket.socket`, `create_connection`,
  `getaddrinfo`, `gethostbyname*` and the methods of already-constructed sockets with a guard. A
  call is refused with `SimulationNetworkError`, recorded as a blocked
  `simulation.boundary_violation` event naming the entry point, and never completes. The
  `finally` restores every entry point, so a simulation cannot leave the process unable to scan.

The runtime half is what covers a collaborator ARACHNE did not write — a dependency that dials, a
replaced composer, a plugin. `tests/test_sim_safety.py` proves both halves, including a
misconfigured collaborator that dials from inside a run.

**If you operate an air-gapped estate, this is the one capability whose safety does not depend on
your network policy at all.**

### 47.2 The estate model: what it is built from (REQ-SIM-001)

The model is built from **stored scan data only**, and the sources are visible by design:

| Part of the model | Where it comes from |
|---|---|
| Hosts | the scan's `assets` rows (plus every host a finding was raised on) |
| Services | the ports and services a scan **observed answering**, read out of the finding evidence |
| Findings | the scan's analyses (verified) and its stored candidates (unverified) |
| Identity relationships | the credential labels a credentialed scan authenticated with, bound only to the host it authenticated to and to any host where an authenticated-area finding was raised |
| Network reachability | the observed services: a port a scan reached is reachability, and a port nobody probed is not |

Three of those deserve a sentence each, because they are where a model could start lying:

- **Reachability is never inferred.** `sim/reachability.py` recognises three documented evidence
  shapes (the port scan's `{"hosts": {host: [ports]}}` map, an inventory's service list, and a
  per-service payload naming **both** `host` and `port`) and ignores everything else. A payload
  nobody documented produces a smaller graph, not a plausible guess — and the graph summary tells
  you how small.
- **Identity bindings are recorded, never inferred.** "Which identity reaches which host" is an
  authorization claim; `build_estate_graph_for_scan` writes a binding only from what a scan
  proved (the credential's own plan target, and hosts with an authenticated-area finding).
- **Paths are composed by the verified report's own composer.** `estate.attack_paths()` calls
  `arachne.analyzer.paths.build_attack_paths` — the same function `## 9. Attack paths` uses. The
  staging rules do not fork: a hypothetical exposure is staged by its CWE exactly as an observed
  one is, a chain still strictly increases through the five stages, and a path's severity is still
  its terminal hop's. A simulation that used looser rules would predict attacks your report would
  never show.

### 47.3 The runbook

```bash
# 1. See what ARACHNE thinks the estate is (read-only; touches nothing).
arachne simulate model --scan 42
arachne simulate model --scan 42 --json > estate.json

# 2. Ask "what if?" with a hypothesis document.
arachne simulate what-if --scan 42 --hypotheses what-if.yaml
arachne simulate what-if --scan 42 --hypotheses what-if.yaml --json

# 3. Compare a proposed design change before/after.
arachne simulate change change.yaml --scan 42

# 4. The trend: re-simulate once, or let continuous mode do it.
arachne simulate trend --scan 42 --estate payments --hypotheses what-if.yaml --run
arachne simulate trend --estate payments --json

# 5. Put the simulated annex into a report a human will read.
arachne report --scan 42 --simulate --hypotheses what-if.yaml --output report.md
```

A hypothesis document is a list of states, each with an id the result will cite:

```yaml
# what-if.yaml
hypotheses:
  - id: public-console            # required: the rendered paths cite it
    kind: new-exposure            # a service/application that becomes reachable
    asset: legacy.example
    port: 8443
    service: https
    note: the legacy console is published by mistake
  - id: leaked-password
    kind: compromised-credential  # a credential an attacker now holds
    asset: db.internal
    identity: portal
  - id: advisory-2026-0001
    kind: new-vulnerability       # a weakness discovered elsewhere
    asset: legacy.example
    title: Unauthenticated RCE in the published console
    severity: critical
    cwe: CWE-89
  - id: rotate-defaults
    kind: applied-fix             # the subtractive kind: closes an observed weakness
    asset: app.example
    target_check_id: m4.default-credentials
```

A change document is the same list plus a name (`name`, `description`, `hypotheses`), and the
delta is reported under that name.

**Exit codes.** `0` when the run completed (including one that found no new path — that is an
answer), `2` on a refusal the operator must act on: an unknown scan, an unparseable document, a
deployment with no simulation store. A *hypothesis* that could not be applied is not an exit code:
it is reported in the run's `refusals` with its reason, because one bad hypothesis is not a failed
run.

### 47.4 Reading a result, and what it never means

Every simulated path carries an origin per hop:

- **`observed`** — a scan established that hop. It appears in the verified report too.
- **`hypothetical`** — the hop exists only because a hypothesis introduced it, and the hop names
  which one. The result never prints the word *verified* about such a hop; the cheapest-break line
  says "hypothetical hop introduced by ..." instead.

Three hard rules you can rely on, and can check:

- **Simulated results never enter a finding store.** Area SIM writes exactly one table,
  `simulation_points`, which holds the trend's headline numbers. Nothing in the package names a
  finding-store writer; `tests/test_sim_safety.py` asserts that over the sources and asserts that a
  real run leaves a real scan's candidate set and severity counts unchanged.
- **Simulated results never enter a CI gate verdict.** The gate counts severities from the
  `findings` table; a report's simulated block lives in its own `simulation` field, which no
  finding-shaped consumer reads. A critical *simulated* path leaves `arachne scan --ci`'s verdict
  untouched, and `tests/report_qa/test_sim_golden.py` pins that.
- **The report renders it in its own section, in every format.** `## 13. Simulated scenarios
  (what-if)` sits *after* the evidence appendix, opens with a plain-language disclosure, and is
  absent unless you asked for it with `--simulate`. A report without a simulation is byte-identical
  to its pre-S28 form, and the verified body (§1–§12) is unchanged by attaching one.

### 47.5 Change simulation: the before/after delta (REQ-SIM-005)

`arachne simulate change` reports the *comparison*, not a score: the paths that exist now, the ones
that would exist after, and the exposure delta, where

> exposure score = Σ over paths of a weight by the path's *business* severity
> (critical 10, high 5, medium 2, low 1, info 0)

A positive delta is worse, a negative one is an improvement. The arithmetic is in
`sim/whatif.py:exposure_score` and is deliberately simple enough to recompute by hand.

```bash
arachne simulate change harden-app.yaml --scan 42
# change: harden-app
# SIMULATED — nothing here was observed on a target.
#
# exposure: 10 → 0 (-10)  paths: 1 → 0
# removed:
#   ap-e7bfc2ce2f4f app.example (terminal critical)
```

One subtlety worth knowing before you read a delta: closing one link of a chain usually *changes*
the path rather than deleting it (a three-hop chain minus its credentials hop is a two-hop chain,
which is a different path id). The delta therefore says "one introduced, one removed" — that is
exact, not a rounding artefact.

### 47.6 Continuous re-simulation and the posture trend (REQ-SIM-006)

Turning this on subscribes the re-simulator to the model-update events (`scan.finished`,
`report.ready`): each finished scan rebuilds the estate model, re-runs the simulation, and appends
a trend point.

```bash
ARACHNE_SIM_RESIMULATE=true          # off by default, like every continuous capability
ARACHNE_SIM_TREND_LIMIT=50           # how many points a read returns
ARACHNE_SIM_MAX_HYPOTHESES=32        # bounds on one run
ARACHNE_SIM_MAX_PATHS=25
ARACHNE_SIM_MIN_CONFIDENCE=55        # the verified-hop threshold (mirrors the report's)
```

Three properties make it safe to leave on: it is opt-in; a failure inside it is a counted error and
never a failed scan (the event bus swallows a raising subscriber, and the re-simulator converts the
failure into an error event); and a provider with nothing to model records **no** point, because a
trend line standing for "no data" would read as "no exposure".

The points feed the posture view, as their own labelled series — never merged into the observed
trend:

```
## Simulated outlook (what-if)

**Simulated.** These points come from re-simulations of the estate model (area SIM), not from
observations of a target: nothing in this section was measured on the estate, and none of it
counts towards the exposure above.

| Re-simulation | Paths | New under hypotheses | Exposure score | Change |
```

### 47.7 Troubleshooting

| Symptom | What it means |
|---|---|
| `no scan to model: run a scan first, or name a scan that exists` | the estate has no scan rows; simulate reads stored data and never scans on demand |
| `the model holds no host 'x': a hypothetical weakness on an asset no scan has seen …` | a hypothesis named a host no scan saw. `new-exposure` is the one kind that may name a new host, because an exposure implies the host behind it |
| `the model holds no observed 'm4.x' weakness on 'y'` | an `applied-fix` can only remove something a scan found; check the check id and the asset |
| the result is empty and you expected a path | a chain needs at least two hops at *increasing* stages. One exposed service is one hop; read `arachne simulate model` to see which stages the estate actually holds |
| `SimulationNetworkError: … simulation.boundary_violation` | something inside the run tried to use the network. This is the safety property working; the audit line names the entry point, and a plugin or a replaced collaborator is the usual cause |
| a model with fewer services than you expect | reachability is read from *documented* evidence shapes only. Check the scan's evidence payloads against `sim/reachability.py`; an undocumented shape is ignored on purpose |

## 48. Detection depth: modern protocols, client code, mobile and OT (S29, area DEPTH)

Area DEPTH widens *what* ARACHNE can inspect without widening *how far* it may go. Six
requirement families arrive here, and every one of them composes with the gates that already
exist: the deny-by-default scope, the active-checks opt-in, the attestation, the proof ladder and
the audit sink. Nothing in this section relaxes a safety mechanism; several of them add one.

The one design decision that shaped the whole area is worth stating before the tables:
**a check never receives the value of a secret found in a response.** Redaction happens at capture
(F-08-04), so a hardcoded key arrives as a detector name and a masked fingerprint. Every
"verification" below therefore proves *impact* — that the thing the credential guards is
reachable without it — and never replays a discovered value.

### 48.1 The new checks, and what each one proves

| Check | Family | Proof | Opt-in | What it establishes |
|---|---|---|---|---|
| `m3.graphql-audit` | GraphQL | L1 | default (active) | introspection enabled (schema disclosure) — since S10 |
| `m3.graphql-depth-abuse` | GraphQL | L1 | **yes** (+ `ARACHNE_WEB_GRAPHQL_PROBE`) | no depth limit (a real cycle in the schema nested `max_depth` levels) and no cost limit (`alias_probe_size` aliases in one operation) |
| `m3.graphql-resolver-auth` | GraphQL | L1 | **yes** (+ same switch) | a resolver whose *name* suggests an authenticated resource answers an anonymous caller |
| `m3.websocket-audit` | WebSocket | L1 | default (active) | the upgrade accepts a reserved attacker `Origin` — since S10 |
| `m3.websocket-upgrade-auth` | WebSocket | L1 | **yes** | the upgrade completes with **no** credential, verified against the RFC 6455 accept derivation |
| `m3.websocket-injection` | WebSocket | L1 | **yes** (+ `ARACHNE_WEB_WS_PROBE`) | the endpoint relays one inert marker frame back (the precondition of message injection) |
| `m2.grpc-plaintext` | gRPC/HTTP-2 | L1 | default (active) | the server answers the HTTP/2 preface, so it speaks cleartext `h2c` |
| `m2.grpc-reflection` | gRPC/HTTP-2 | L1 | default (active) | the standard reflection method returns a descriptor response |
| `m2.grpc-metadata-leak` | gRPC/HTTP-2 | L1 | default (active) | request metadata (an inert nonce) comes back in the response body |
| `m1.js-asset-scan` | client code | L1 (hybrid) | default (active) | secrets by detector kind **and** DOM sink/source shapes in served bundles — extended in S29 |
| `m3.client-secret-verify` | client code | **L2** | **yes** | the API route a bundle names answers a caller presenting nothing; the ladder's single-use token confirms it out of band when a callback is configured |
| `m1.mobile-artifact` | mobile | **L0** | **yes** | an offline APK/IPA's hardcoded secrets (masked) and the endpoints it names, recorded as assets for M1/M3 |
| `m2.ot-protocol-probe` | OT/ICS | L1 | **yes twice** (+ `ARACHNE_NET_OT_PROBE`) | an S7comm or DNP3 endpoint answers a read-only request from the scanned segment |
| `m2.ics-probe` | OT/ICS | L1 | **yes** (+ UDP) | Modbus/BACnet device discovery — since S4 |

Two properties hold for every row. **Every probe is content-free where it can be**: the GraphQL
depth and authorization probes select only the introspection meta-field `__typename`, so a finding
proves a resolver *ran* without asking the server for a single document field. And **every dynamic
probe is inert**: one marker nonce, one frame, one connection — no payload, no mutation, no
state change, and (for the OT checks) no read or write of controller memory.

### 48.2 GraphQL: depth, cost and resolver authorization

`m3.graphql-audit` stays what it was: it reports an exposed schema. The two new checks read that
schema and ask two harder questions.

```
arachne scan --target targets/prod.yaml --active-checks --check m3.graphql-depth-abuse
ARACHNE_WEB_GRAPHQL_PROBE=true ARACHNE_WEB_MAX_PARAMS=8 arachne scan --target targets/prod.yaml \
  --active-checks --check m3.graphql-depth-abuse --check m3.graphql-resolver-auth
```

- **Depth** — the check walks the introspected *type graph* to a real cycle (`product → vendor →
  products → …`) rather than guessing field names, and nests the selection `graphql.max_depth`
  levels (payload default **12**). A server with a depth limit answers with an error carrying one
  of the corpus's refusal markers; a server without one answers with data. The message says which
  of the two halves fired.
- **Cost** — one operation carrying `graphql.alias_probe_size` aliases (default **32**) of
  `__typename`. `alias_abuse_threshold` (default **24**) is how many returned results count as "no
  cost limit", so a server that silently truncates is not reported.
- **Resolver authorization** — for each query field whose name matches
  `graphql.sensitive_field_hints` (`adminusers`, `invoices`, `secrets`, …) the check sends
  `{ field { __typename } }` with **no credential** (the request is issued on the client's
  cookie-less path, so not even a cookie the crawl picked up is attached), and uses a query for a
  field that cannot exist as the control. Data from the first and an error from the second is the
  finding. Only the meta-field is selected: the authorization gap is proven without reading the
  data behind it.

All the probe text lives in `src/arachne/templates/m3/payloads.yaml` under `graphql:` (managed
data, F-09-04), so an operator can retune the depth, the alias count and the field-name hints
without touching code.

### 48.3 WebSocket: origin, upgrade authentication and message relay

`m3.websocket-audit` answers "does the endpoint validate `Origin`?". Two more facets matter, and
each has its own check because each has its own remediation:

- **Auth on upgrade** (`m3.websocket-upgrade-auth`) — the handshake is built at the byte level and
  carries no `Authorization`, no `Cookie`, no subprotocol token and no demo session. The accept
  header is verified against the RFC 6455 derivation of the key that was sent (so a path that
  merely answers `101` is not reported), and a plain `GET` of the same path is the control: a
  WebSocket endpoint answers "upgrade required". Because the bytes are built by the check, "no
  credential was presented" is a fact about the request rather than an assumption about a client's
  cookie jar.
- **Message relay** (`m3.websocket-injection`, `ARACHNE_WEB_WS_PROBE=true`) — one text frame
  carrying `ARACHNE_POC_<nonce> safe-proof-of-websocket-message-relay` plus one control `PING`.
  A server that echoes the marker back is relaying unvalidated client input; the finding says
  relay and nothing more, and the artifact records `payload_executed=false`, `messages_sent=1`.
  The message template is `websocket.message_template` in the payload corpus.

Both are read-only. Neither can express a command, a query language or target-specific syntax.

### 48.4 gRPC and HTTP/2

Three checks run against the ports the **port catalogue** declares with `probe: grpc` (the shipped
catalogue names 50051):

```
# where a gRPC service actually lives, in the operator's catalogue
tcp:
  - {port: 50051, service: grpc, probe: grpc}
```

- `m2.grpc-plaintext` sends the HTTP/2 connection preface (h2c prior knowledge) and reports a
  `SETTINGS` answer: the endpoint speaks cleartext HTTP/2, so method, body and metadata travel
  unencrypted.
- `m2.grpc-reflection` calls `/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo` and
  reports a descriptor response.
- `m2.grpc-metadata-leak` attaches a unique inert nonce as `authorization` and `x-arachne-nonce`
  metadata and reports a response carrying the nonce back.

The framing is hand-rolled (no `grpcio` dependency, and no second egress path around the scoped
network client). One limitation is stated rather than hidden: **HPACK Huffman-coded header strings
are not decoded** — such a field is reported as undecoded. Nothing in these checks depends on it
(the plaintext signal is a frame type; the reflection and leak signals are bytes in the response
body), so a target that Huffman-codes its headers is still measured correctly.

### 48.5 Client-side code: static shapes and dynamic verification

`m1.js-asset-scan` now reports two static readings of every served bundle:

- **secrets**, as detector names with masked values (unchanged);
- **DOM sink/source shapes** — the sinks of `extract.DOM_SINK_FAMILIES` (`innerHTML`,
  `document.write`, `eval`, `dangerouslySetInnerHTML`, …) together with the attacker-influenceable
  sources (`location.search`, `location.hash`, `URLSearchParams`, …). A sink that appears with a
  non-empty value in a body that also reads a source is the *static precondition* of a DOM-XSS
  path. No JavaScript engine runs (ADR-100.4), the confidence is deliberately modest (0.4), and
  the evidence says so in as many words.

`m3.client-secret-verify` is the dynamic half, and it is **L2** — opt-in, and it asks the ladder
for a single-use callback token:

```
ARACHNE_WEB_SSRF_CALLBACK=https://callback.internal.example \
  arachne scan --target targets/prod.yaml --active-checks --check m3.client-secret-verify
```

What it does: reads the bundles on the origin, collects the API routes they name, and asks each one
— **anonymously**, on the client's cookie-less path — whether it answers. The route that answers is
the finding, because a client-side credential that guards nothing is the impact worth reporting.
The callback token goes into a URL-valued parameter of that route when one exists, and the target's
own connection back to ARACHNE confirms it out of band. Three facts are recorded in the artifact:
`anonymous_request`, `out_of_band_confirmed` and `proof_level` (`L2` when the callback fired, `L1`
when no callback base is configured — the ladder's documented downgrade, REQ-PROOF-003).

### 48.6 Mobile artifacts, offline (APK/IPA)

A mobile artifact is a **target of its own kind**:

```yaml
target:
  name: android-build
  targets:
    - kind: artifact
      value: /srv/builds/android/lab-app.apk
  attestation:
    attested_by: "Jane Operator <jane@example.com>"
    attested_at: "2026-11-01T00:00:00Z"
    scope_statement: "Offline analysis of our own signed build outputs under /srv/builds"
    allowed_targets: ["/srv/builds"]      # must cover the declared artifact
    active_checks_authorized: false       # the artifact check makes no request
```

- The path must be **absolute**; `~` is expanded and the value is normalised lexically.
- Reading it is a **scope decision**: `Scope.allowed_artifacts` is a deny-by-default dimension of
  its own, compiled from the declared artifact target — the filesystem analogue of
  `url_prefixes`. The attestation's `allowed_targets` must additionally *cover* the declared
  artifact, so declaring the file is not enough on its own: it also has to be authorized. A path
  the scope does not grant is refused, and `arachne scan --dry-run` prints the dimension so an
  operator can see it before anything is read.
- The check is **opt-in** and declares **L0**: it contacts nothing at all. It makes zero network
  requests, executes nothing, decompiles nothing and unpacks nothing — the zip container is read as
  bytes and its code and manifest entries are decoded as text.
- Findings: credential patterns as detector names (values masked, F-08-04), and the endpoints the
  artifact names, **recorded as assets** so M1 and M3 pick them up on the next scan.

`tests/test_depth_safety.py` proves the offline claim the way the platform proves zero-network
simulation: every socket entry point is armed and the test fails if one is reached — while also
asserting the planted secret *was* found, so the check cannot pass by doing nothing.

### 48.7 OT/ICS, read-only and strictly opt-in

Modbus and BACnet live in `m2.ics-probe` (S4). S29 adds S7comm and DNP3 in
`m2.ot-protocol-probe`, and both are opt-in *twice*: the check is outside the default set, and the
deployment switch must be on.

```
ARACHNE_NET_OT_PROBE=true arachne scan --target targets/plant.yaml \
  --active-checks --check m2.ot-protocol-probe
```

- **S7comm** — an ISO-TSAP COTP *connection request* and nothing else. The connection confirm is
  the finding: a PLC's engineering protocol answers from the scanned segment. **No read-var job,
  no write-var job, no PLC memory access** — the check cannot express one.
- **DNP3** — the link-layer `REQUEST_LINK_STATUS` function only. The reply is CRC-verified. The
  code cannot send `RESET_LINK_STATES`, because that would change the outstation's link state
  machine; `wire.dnp3_link_status_request` is the only DNP3 frame the scanner builds.
- Where the ports live is the port catalogue's business: `probe: s7` (102) and `probe: dnp3`
  (20000) in the shipped catalogue, and the operator's catalogue wins.

Both facets report the reachability itself as the finding, because that *is* the bad
configuration: an OT protocol has no authentication in the base protocol, so if it answers from a
business network, the segmentation that should have prevented it is missing.

### 48.8 The switches, in one place

| Variable | Default | What it enables |
|---|---|---|
| `ARACHNE_WEB_GRAPHQL_PROBE` | off | the GraphQL depth/cost and anonymous-resolver probes |
| `ARACHNE_WEB_WS_PROBE` | off | the one-frame WebSocket message-relay probe |
| `ARACHNE_WEB_SSRF_CALLBACK` | unset | the out-of-band base the L2 checks need; without it `m3.client-secret-verify` reports its L1 downgrade |
| `ARACHNE_NET_OT_PROBE` | off | the read-only S7comm/DNP3 probes |
| `ARACHNE_NET_ALLOW_UDP` | off | the UDP half of `m2.ics-probe` (SNMP, BACnet) |

And the per-check opt-in remains whatever it always was: name the check
(`--check m3.client-secret-verify`), keep `--active-checks` on, and make sure the attestation
covers the target. An L2 check that is not named is not planned, and a scan without the
attestation never reaches the target at all.

### 48.9 Troubleshooting

| Symptom | What it means |
|---|---|
| `the GraphQL depth/cost probe is off: set ARACHNE_WEB_GRAPHQL_PROBE=true` | the switch is the gate; the check is off by design and says so instead of reporting a clean result |
| the depth probe reports nothing but the endpoint has introspection | the schema offered no cycle to nest along. The result says so (`no introspectable cycle`); the cost probe still ran |
| `the depth limit could not be tested` | same cause: without a self-referential object field the check will not guess a name |
| a WebSocket endpoint is not reported by `m3.websocket-upgrade-auth` | either the accept header did not match the RFC 6455 derivation of the key that was sent, or a plain `GET` of the path did not answer "upgrade required" — both are deliberate controls against `101`-shaped replies that are not handshakes |
| `no network client in this run` on a WebSocket check | the checks are driven at the byte level from a live scan; a dry run sends nothing (F-01-10) |
| `artifact not analyzed: refusing a relative artifact path` | the target must be an absolute path; relative values are ambiguous and are refused rather than resolved |
| `artifact ... is not in the declared scope` | the artifact path is not covered by a declared target or an attestation path entry. Add the root to `allowed_targets` |
| `OT/ICS probing is off: set ARACHNE_NET_OT_PROBE=true` | the second opt-in. Reaching an OT protocol is itself the sensitive act |
| a gRPC check reports nothing on a port you know serves gRPC | the port is not declared with `probe: grpc` in the port catalogue ARACHNE is using, so the check never looked there |

---

## 49. Bounded safe fuzzing (S30, area FUZZ)

Area FUZZ finds the unknown-unknowns in parsers and inputs. It is the one capability in this
program whose *purpose* is to send traffic a normal scan would not, so it is also the one with the
most machinery around it: its own grant, its own hard bounds, a prohibition table applied to
generated bytes, and a guard that stops the run at the first sign the target is not coping.

The rule the whole area is built on: **discovery, never disruption**. Fuzzing here produces
*candidates*, never findings — a candidate is a lead that has to be verified through the proof
ladder (area PROOF) before anything is reported as a vulnerability.

### 49.1 What it is not

| Not this | Because |
|---|---|
| A source of findings | Only the proof ladder reports (REQ-FUZZ-003/004). A candidate carries no severity and no verdict, and there is no code path from a fuzzing run to a reported vulnerability |
| A random byte generator | Every mutation is grammar-aware: a declared field, a named operator, and a message that is still well-framed. A random-byte mode would produce inputs a protocol implementation is designed to reject, which finds nothing |
| A way to fuzz production | The fuzzing attestation defaults to non-production targets only, an unclassified environment is refused rather than assumed, and permitting production needs *both* the grant and the deployment to say so |
| A write-operation tool | A grammar's operation field is confined to a declared read-only allowlist. A state-changing Modbus function code, an S7 Write Var, a DNP3 operate, an SNMP SetRequest, an LDAP modify are all *unrepresentable* — the grammar refuses to be defined with one |
| A shell | The payload table refuses shell metacharacters, destructive commands, remaining-infrastructure verbs, destructive SQL and obfuscation encodings, and a payload the table refuses is discarded inside the process before any socket is written |
| A long-running service | Every run has hard per-target bounds: cases, requests and wall-clock seconds. Exhausting one ends the run and still produces a report |

### 49.2 The four commands

```bash
arachne fuzz limits                    # the deployment's ceilings and the prohibition table
arachne fuzz engines --verbose         # the engines and the message grammars (+ fields)
arachne fuzz check  plan.yaml          # parse + authorize + report; sends nothing
arachne fuzz run    plan.yaml -o out.json
```

`limits` and `engines` are read-only and are how an operator answers "what will this deployment
let me do?" and "what can it actually mutate?" before writing a plan. `check` is the verb to run
in a change review: it resolves the bounds, counts the cases per target, and authorizes the plan —
and dials nothing. `run` exits non-zero when it refuses a plan, when it aborts, and zero when it
completes within its bounds; a bound that stopped the run early is reported in the output.

### 49.3 A plan document

```yaml
schema_version: "1.0"
fuzz:                                  # the area's own grant (REQ-FUZZ-001)
  attested_by: owner <owner@example.test>
  attested_at: "2026-10-01T00:00:00Z"
  scope_statement: "Authorization to fuzz the staging lab"
  allowed_targets: ["lab.example.test", "10.20.0.0/24"]
  environment: staging                 # non-production label; see §49.4
  # allow_production: true            # explicit, and still subject to the deployment ceiling
budget:                                # what this run asks for — clamped down, never up
  max_cases: 200
  max_requests: 220
  max_seconds: 60
  batch_size: 25
target:                                # the *scan* grant this run inherits
  name: staging-lab
  targets:
    - kind: domain
      value: lab.example.test
  attestation:
    attested_by: owner <owner@example.test>
    attested_at: "2026-10-01T00:00:00Z"
    scope_statement: "Authorization for the staging lab"
    authorization_ref: CR-1234
    allowed_targets: ["lab.example.test"]
    active_checks_authorized: true
wire:
  - label: s7-peer
    grammar: s7.cotp-connect           # a shipped grammar; see §49.6
    host: lab.example.test
    port: 102
http:
  - label: staging-web
    parameters:
      - url: "https://lab.example.test/search?q=1"
        parameter: q
    families: [boundary, sqli-error, xss-reflection]
engine: grammar
notes: "part of CR-1234"
```

Both grants are required. The `target:` block is the *inherited* gate — the scope, the active-check
permission, the expiry — and indexing it here means one schema for target definitions in the whole
program. The `fuzz:` block is the area's own and is the harder one to obtain.

### 49.4 The fuzzing attestation, and environments

`environment` is a hint the operator declares, and it decides production-ness together with
`allow_production`:

| Declared `environment` | Result by default |
|---|---|
| `lab`, `test`, `dev`, `staging`, `qa`, `uat`, `preprod`, `sandbox`, `demo`, `canary`, `training`, … | permitted |
| `prod`, `production`, `live`, `customer`, … | **refused** unless the grant sets `allow_production: true` |
| anything else (`dmz-3`, `ops`, a typo) | **refused** — an unclassified environment is not silently treated as a lab |

`allow_production: true` is necessary but not sufficient: the deployment must also set
`ARACHNE_FUZZ_ALLOW_PRODUCTION=true`. One mis-scoped grant therefore cannot turn a lab-only
installation into a production fuzzer. Every authorization and every refusal is audited
(`fuzz.authorized` / `fuzz.refused`), the refusal is written *before* it is raised, and the runner
authorizes before it builds a client — so an unattested request cannot reach code that could open
a socket.

### 49.5 The bounds and the guard

| Setting | Default | What it bounds |
|---|---|---|
| `ARACHNE_FUZZ_MAX_CASES` | `200` | mutated messages per target |
| `ARACHNE_FUZZ_MAX_REQUESTS` | `220` | requests per target — a case can cost more than one, and health probes count |
| `ARACHNE_FUZZ_MAX_SECONDS` | `60` | wall-clock seconds per target |
| `ARACHNE_FUZZ_BATCH_SIZE` | `25` | cases between the health probes that bracket a batch |
| `ARACHNE_FUZZ_ENGINE` | `grammar` | the engine a plan gets when it names none |

A plan may ask for **less** than any of these and never for more: a request above the ceiling is
clamped (and `fuzz check` says which fields were clamped). A grant's own `max_cases`,
`max_requests` and `max_seconds` are a second ceiling on top of the plan's request.

The abort guard (REQ-FUZZ-005) is what makes "never disruption" enforceable rather than aspirational:

| Setting | Default | The signal |
|---|---|---|
| `ARACHNE_FUZZ_HEALTH_MIN_SAMPLES` | `3` | samples before the rate signals are judged |
| `ARACHNE_FUZZ_MAX_ERROR_RATE` | `0.34` | probe error rate |
| `ARACHNE_FUZZ_MAX_TIMEOUT_RATE` | `0.25` | probe timeout rate |
| `ARACHNE_FUZZ_MAX_LATENCY_RATIO` | `4` | probe latency against the pre-batch baseline |
| `ARACHNE_FUZZ_MAX_CONSECUTIVE_FAILURES` | `2` | consecutive probe failures |

A run is structured as batches, each bracketed by a **health probe** — an ordinary well-formed
request whose answer is checked against the shape a healthy target returns — with more probes
interleaved inside the batch. The guard is re-judged after **every** case, so the run stops at the
first degradation signal rather than at the end of a batch that has already done twenty more things
to a struggling service. An abort stops the **whole run**: a fuzzer that has just made one service
struggle does not move on to the next. It is audited as `fuzz.aborted` with the measured signal,
and it is a non-zero exit code.

Two distinctions the guard turns on, and both are deliberate:

- **A target refusing a malformed message is healthy.** A DNS RCODE, a Modbus exception, an HTTP
  500 to a fuzzed parameter — that is the parser doing its job, and it is the source of the
  candidates a run is looking for. Only *probe* results, transport failures and (on TCP) a
  connection that answers nothing feed the guard.
- **A target that is already failing is not fuzzed at all.** If the baseline probes do not pass,
  the run refuses that target (`fuzz.refused`) rather than attributing its failure to the fuzzing.

### 49.6 What it mutates

`arachne fuzz engines --verbose` prints the shipped set. Ten grammars, each built on the real
builder the shipped M2 checks use, so the seed is the message a check actually sends:

| Grammar | Protocol | What the mutations reach |
|---|---|---|
| `dns.query` | DNS | header counts, flags, the question name, QTYPE/QCLASS |
| `snmp.get` | SNMP | every BER definite length, the community, the PDU tag, the first OID |
| `modbus.read-device-id` | Modbus | the MBAP length, unit id, function code, MEI objects |
| `s7.cotp-connect` | S7comm | the TPKT length, the COTP PDU type, refs, TSAP parameters |
| `dnp3.link-status` | DNP3 | the link length and control byte, with the CRC recomputed |
| `rdp.negotiation` | RDP | the TPKT length, the X.224 CR, the negotiation block (little-endian) |
| `ntlmssp.negotiate` | NTLMSSP | the security-buffer lengths and offsets, the flags |
| `redis.ping` | Redis | the RESP counts and bulk length, the verb |
| `postgres.startup` | PostgreSQL | the startup length, the protocol version, both parameters |
| `tls.client-hello` | TLS | the record, handshake, cipher-suite and extension lengths |

Every grammar is validated against its own seed at import: a framing that does not describe the
message, a checksum that does not verify, or an operation field holding a state-changing operation
is a *construction* error, not a fuzzing surprise. Two grammars additionally recompute a checksum
(`dnp3.link-status` recomputes its CRC so the target's link layer passes the frame to the parser)
and add a `corrupt-checksum` operator, because "does the target verify its checksum at all" is
itself a finding.

The operators are named, closed and enumerable, so a report says exactly what was tried: numeric
boundaries (`zero`, `one`, `max`, `max-minus-one`, `plus-one`, `minus-one`), framing
inconsistencies (`length-zero`, `length-over`, `length-under`, `length-max`), legal-but-different
operation values, text boundaries, and region shape (`drop-field`, `repeat-field`, `extend-field`,
`fill-zero`, `fill-max`).

### 49.7 Candidates, and what happens to them

A candidate names the grammar, the field, the operator, the exact payload (digest and a bounded
hex preview), the signal it produced, and **which check could prove it**:

| Signal | Verifier |
|---|---|
| `error-leak` (a database error signature) | `m3.sqli-oracle` |
| `file-read` (a traversal marker) | `m3.traversal-oracle` |
| `reflection` (an unencoded probe marker) | `m3.xss-oracle` |
| `timing` | `m3.sqli-oob` |
| `fault`, `divergence`, `anomaly`, `no-response` | *none — recorded for manual triage* |

A candidate with a verifier becomes a `Hypothesis` for the S21 pipeline (`candidate.to_hypothesis()`)
and is verified under the planner, the scope gate and the proof gate that any other probe goes
through. A candidate **without** one is still recorded — "we saw something odd on this peer and
nothing here can prove it" is information an operator needs — and says so: naming a check that
cannot prove the claim would manufacture a verification that did not happen.

### 49.8 The two engines

| Engine | What it does | What it needs |
|---|---|---|
| `grammar` (default) | the declared case plan, in declaration order, no feedback | nothing — standard library only |
| `fingerprint` | re-prioritises the field that produced a response *shape* no earlier case produced | nothing — also standard library only |

`fingerprint` is **not** a coverage-guided engine and says so in its own description, which the
report renders. Its signal is novelty in the response, which is a proxy; real coverage needs target
instrumentation (edge counters, a sanitizer build), and that is a decision about the *target* — out
of scope for a default install. REQ-FUZZ-006 asks for the pluggable interface and permits (does
not require) a coverage-guided engine; the dependency set is unchanged, and a test pins it.

An engine answers two questions — `plan(grammar, limit)` and `observe(outcome)` — and sees neither
the budget, nor the network, nor the audit trail. A third-party engine can therefore change *which
mutations get tried* without being able to change what a run is allowed to do.

### 49.9 Reading a result

`arachne fuzz run` prints the run's stop reason, the per-target counts, and every candidate. The
JSON report (`-o`) carries the same plus, for each target: the health baseline (three probes with
latencies), the post-batch probes, the batch count, the ledger's spend, and the candidate list with
`"is_finding": false` restated on every row. The audit trail carries `fuzz.authorized`,
`fuzz.health` (one line per probe, with its phase), `fuzz.candidate`, `fuzz.payload_refused`,
`fuzz.batch_complete`, `fuzz.aborted`/`fuzz.budget_exhausted` and `fuzz.finished` — plus the
`net.probe`/`http.request` line every case leaves through the egress client. There is deliberately
no per-case audit action: a second line saying what `net.probe` already says would double the trail
without adding an answer.

"Healthy after: yes" is the claim that the run did not disturb the target, and it is evidence
rather than assertion: it means every probe after every batch answered the way a healthy target
does, and the probe samples are in the report.

### 49.10 Troubleshooting

| Symptom | What it means |
|---|---|
| `fuzzing refused: ... no fuzzing attestation` | the plan has no `fuzz:` block. A scan grant alone never authorizes fuzzing |
| `... inherits the scan's authorization` | the `target:` block has no attestation. Fix that first; the fuzzing grant extends it |
| `... environment 'prod' is production and the fuzzing attestation does not permit production targets` | declared non-production only, by default |
| `... environment 'dmz-3' is neither a declared non-production label nor a production one` | the label is not in the table in §49.4. Set `environment: staging` (or whichever tier it is) rather than inventing a label |
| `... this deployment has not opted in (ARACHNE_FUZZ_ALLOW_PRODUCTION)` | the grant permits production and the deployment does not. Both must agree |
| `the target did not pass its own health probe before fuzzing` | the run refused to start against a target that was already failing. Fix the service, or check the port and grammar |
| `fuzz.payload_refused` in the trail and no case in the report | an engine generated a prohibited payload; it was discarded before any socket was written. With the shipped engine this means a custom grammar or a third-party engine — the audit `detail` names the class |
| `stopped: probe latency ... is 12.3x the 1ms baseline` | the abort guard fired on a real slowdown. The run stopped; nothing else was sent |
| every candidate has `needs-manual-triage` | no shipped check can prove that signal. That is the honest answer, not a defect |
| a run that stops immediately with `budget-exhausted` | the plan asked for a case/request/second bound smaller than the baseline probes need. Raise it, or set `ARACHNE_FUZZ_*` if the ceiling clamped it (`fuzz check` says so) |
### 37.1 Anchoring

```bash
arachne integrity anchor                              # checkpoint the current head
arachne integrity anchor --export /safe/anchor.json   # …and keep a copy off the host
arachne integrity seal --scan 42                      # (re)seal a scan
```

Anchoring is automatic too: `ARACHNE_INTEGRITY_ANCHOR_EVERY=1000` writes one every thousand
audit rows. **Export an anchor somewhere the database cannot reach.** An anchor that lives only
in the database it guards can be deleted along with the evidence of the deletion; a copy on
another host cannot.

### 37.2 What to do when it fails

| Finding | What it means | First move |
|---|---|---|
| `modified` on an audit row | the stored event content was edited | treat the trail as compromised; preserve a copy before anything else |
| `deleted` / `reordered` | rows were removed or moved | compare against your exported anchors to bound *when* |
| `audit-signature` | the row, or the signature, was forged | rotate `ARACHNE_INTEGRITY_KEY`; the key may be exposed |
| `seal: … is gone` | a finding or evidence row was deleted after the scan completed | restore from a bundle and compare |
| `anchor: trailing row(s) were deleted` | the log was truncated | an exported anchor tells you how far back the damage goes |
| `unsigned` | no `ARACHNE_INTEGRITY_KEY` is configured | set one; without it nothing can be verified |

Never "fix" a failing chain by deleting the failing rows. A gap is a record.


## 50. Re-verifying one finding: `arachne verify-finding` (WP-13, REQ-PROOF-016)

```bash
arachne verify-finding 42            # re-run finding 42's own check against the same asset
arachne verify-finding 42 --json     # the verdict as a document, for a script
arachne verify-finding 42 --actor "alice@example.com"
```

Every finding carries a **verification record**: the proof level it was established at, the
method, the observations, a reproducibility token, when it was verified and which version of the
check did it. `verify-finding` re-runs *that* check — and nothing else — against the same asset,
then records the new result as a new record linked to the one it re-checked.

It answers one of four things:

| Verdict | Exit | Meaning |
|---|---:|---|
| `still-verified` | 0 | the check ran against the asset and reported the finding again |
| `no-longer-verified` | 0 | the check ran cleanly and reported nothing; the proof no longer holds |
| `inconclusive` | 0 | the check could not run (skipped, failed, no recorded line) — neither confirmed nor refuted |
| `refused` | 1 | nothing was re-checked: an expired or non-covering attestation, an out-of-scope asset, no verification record, or a check that would need a **higher** proof level than the finding was recorded at |

Three properties worth knowing as an operator:

- **Scope and attestation are re-checked before any network access.** The command re-uses the
  scan's own gates on the request document the original scan stored, so an attestation that has
  since expired refuses the re-verification exactly as it would refuse a scan — and the refusal is
  audited (`finding.reverify_refused`) with nothing dialled.
- **The level never rises.** A check that has grown a stronger proof since the finding was
  recorded is refused rather than run up a rung (PD-7). To establish a stronger claim, run a scan
  with the attestation that authorizes it.
- **A finding whose re-verification does not confirm it is reported at severity `info`.** Its
  report entry shows the record as `unverified`, so a stale severity cannot outlive its proof.
  The audit trail carries both records: `finding.verification_recorded` for the parent and
  `finding.reverified` for the new one.

---

## 51. Performance envelope and false-positive rate (WP-17, REQ-SCALE-009/012/013, REQ-QUAL-009)

The full detail, the method and the caveats are in [performance.md](performance.md). What an
operator needs here:

**The published envelope** (measured 2026-11-04, AMD Ryzen 5 5600H, 12 CPUs, 15,380 MiB,
CPython 3.14.9, SQLite, heuristic engine, 10 scans / 100 findings):

| Endpoint | p95 at 50 req/s |
|---|---:|
| `GET /api/v1/scans` | 20.60 ms |
| `GET /api/v1/findings` | 18.90 ms |
| `GET /api/v1/targets` | 12.58 ms |
| `GET /api/v1/modules` | 12.83 ms |

Scan throughput on the reference lab: **87.8 checks per minute per agent**; peak RSS growth
during that scan 14.6 MiB against a 1,024 MiB ceiling. The budget for every endpoint is p95
≤ 500 ms.

**Re-measure it with one command**, and commit the result with the release:

```bash
python -m arachne.tools.envelope --write benchmarks/envelope/envelope.json
python -m arachne.tools.envelope --gate      # 0 = inside budget and the committed margin
```

`--skip-scan` measures the API only; `--duration` and `--rate` change the load.

**The false-positive rate** is measured on the in-repo ground-truth corpus
(`tests/lab/web_lab.py`, suite `arachne-lab` 1.0):

```bash
python -m arachne.tools.benchmark --lab --write-baseline   # measure and commit
python -m arachne.tools.benchmark --lab --gate             # release gate
```

The published figure is **0 false positives / 15 scored candidates = 0.0 %**, against a
release ceiling of **2 %**. The denominator is the scored candidates only (true positives +
false positives); the 14 candidates outside the corpus's ground truth are reported as
*unscored* and are deliberately not counted as false positives — see
[performance.md](performance.md) §6 for why, and for the honest reading of a small-corpus
zero.

**Read replicas.** Set `ARACHNE_DATABASE_REPLICA_URLS` (comma-separated) to serve the
read-only catalogue/listing endpoints from a replica. Writes always go to the primary; reads
through a replica may lag the last write. A replica that stops answering degrades to the
primary with a `db.read_replica_fallback` log line and the
`arachne_read_replica_failovers_total{replica=...}` counter, retried once per 30-second
cooldown rather than once per request.

**Release checklist.** `tests/perf` green, both gates above passing, and the two
`benchmarks/` JSON files committed. The full list is in [performance.md](performance.md) §8.

## 52. Service-level objectives and error budgets (WP-18, REQ-OPS-007)

This is the runbook the alerts link to. The objectives, the budgets and the alert rules are
versioned artefacts in the repository, not panels in somebody's Grafana:

| Path | What it is |
|---|---|
| `deploy/observability/slos/` | the objectives: target, window, measurement query |
| `deploy/observability/alerts/arachne-slo-burn.yaml` | the generated recording rules and burn alerts |
| `deploy/observability/dashboards/arachne-slo.json` | the generated Grafana dashboard, one panel pair per objective |

A dashboard is a shipped artefact for the same reason the alerts are: a panel measuring the
wrong thing is indistinguishable from a healthy service. Both files are generated from the
definitions (`deploy/observability/README.md` says how to load them), and both are checked —
`--check` fails when either has drifted, and every PromQL expression a panel carries goes
through the same metric contract as the definitions themselves.

```bash
arachne slo show                 # every objective: target, budget, query, alert thresholds
arachne slo check                # the contract test + a check that the rules are in step
python -m arachne.ops.slo --render   # rewrite the alert rules from the definitions
```

The contract test (`tests/unit/test_slo_contract.py`) resolves every metric, label and
histogram bucket a definition names against the families `GET /metrics` actually exposes. A
definition that measures something nobody publishes fails there, rather than turning into an
empty panel that reads as "healthy".

**The three objectives**

| Objective | Indicator | Target | Window |
|---|---|---|---|
| `api-availability` | requests answered outside 5xx ÷ all requests | 99.9 % | 30 d |
| `api-latency` | requests within 500 ms ÷ all requests | 99 % | 30 d |
| `scan-completion` | scans completed ÷ finished scans | 95 % | 7 d |

A 4xx is **not** an error-budget event here: the API is authenticated and deny-by-default, so a
rejected request is the control working. `aborted` scans are not failures either — an operator
cancelling a scan is a decision. Both exclusions are stated in the definition files.

### 52.1 Availability: the API answers

*What fired:* `ArachneSloApiAvailabilityPageBurn` (fast) or `…TicketBurn` (slow).

*What it means.* The fraction of requests answered outside 5xx is below 99.9 % over the window,
and the deployment is spending its error budget faster than 14.4× (page) or 6× (slow ticket).

*First moves.*

1. `arachne metrics | grep arachne_api_requests_total` — which status class is moving: `5xx`
   rising, or total traffic collapsing (a scrape-target problem, not an outage)?
2. `kubectl logs` / `journalctl` for `level=ERROR` in the last hour; a 5xx from ARACHNE is
   almost always a store or a credential problem, not the network.
3. `arachne db current` — a half-applied migration is the classic cause of a 5xx spike.
4. If the cause is a bad release: `arachne db upgrade --dry-run` before any rollback, and
   `tests/unit/test_migrations.py` tells you which revisions can be reversed.

*Do not:* silence the alert to get the budget back. The budget is the measurement; the fix is
the response.

### 52.2 Latency: the API is fast enough

*What fired:* `ArachneSloApiLatencyPageBurn` (fast) or `…TicketBurn` (slow).

*What it means.* Fewer than 99 % of requests are answered within 500 ms — the same 500 ms
ceiling `python -m arachne.tools.envelope --gate` holds a release to.

*First moves.*

1. `python -m arachne.tools.envelope --gate` on the current build: is this a regression, or did
   the estate grow past the measured envelope?
2. `python -m arachne.tools.envelope` prints the hardware and dataset it measured on; a p95 that
   moved without a dataset change is a regression against the committed
   `benchmarks/envelope/envelope.json`.
3. Check the read path: a report+analysis read is budgeted at 8 queries; the measured count is
   in the envelope report. A rising count means an endpoint lost its batching.
4. `arachne db tables` and the database's own slow-query log — an unindexed scan over
   `findings` shows up here first.

### 52.3 Scan completion: the queue drains

*What fired:* `ArachneSloScanCompletionPageBurn` (fast) or `…TicketBurn` (slow).

*What it means.* More than 5 % of finished scans are failing. Only `completed` and `failed`
count: a queue that is merely long is not a completion failure.

*First moves.*

1. `arachne dr status` — queue depth, live leases and the scaling decision in one view.
2. `arachne metrics | grep -E 'arachne_scans_total|arachne_queue_'` — failures by status, and
   whether the farm is scaled to the queue.
3. `arachne scans list` (or the UI) for the failing scans, then `arachne report` on one of them:
   a systematic failure names its cause in the audit trail.
4. If the failures are target-side (timeouts against one estate), it is a scope or an attestation
   conversation, not a capacity one.

### 52.4 The alerts, and what to do at 3 a.m.

Each objective gets two burn-rate alerts, the multi-window pair from the SRE workbook:

| Rule | Threshold | For | Severity |
|---|---|---|---|
| `…PageBurn` | 14.4× the budget (2 % of a 30-day budget in 1 h) | 2 m | `page` |
| `…TicketBurn` | 6× the budget (5 % in 6 h) | 15 m | `ticket` |

The burn rate is `(1 - SLI) / error_budget`, computed by a recording rule the same file
defines, so what the alert compares against its threshold is the arithmetically meaningful
quantity rather than a ratio to convert in your head. Both alerts carry `slo`, `service` and
`owner` labels and a `runbook_url` pointing at the relevant subsection above.

**At 3 a.m., the fast alert is the one to act on.** It fires within minutes of a real outage and
it is designed to be rare; the slow alert is a ticket you triage in the morning. If a fast alert
fires and the service looks fine, suspect the *measurement* — a scrape target that stopped being
scraped shows up as a collapsing denominator — before you suspect the alert.

### 52.5 Changing an objective

1. Edit the definition in `deploy/observability/slos/`.
2. `python -m arachne.ops.slo --render` to regenerate the alerts.
3. `arachne slo check` — it fails if a definition names a metric the endpoint does not expose,
   if the objective window is not the window the query measures, or if the committed rules and
   the definitions disagree.
4. Update the subsection above if the response changed. An alert whose runbook is wrong is worse
   than no alert.

## 53. Mutation testing the safety core (WP-18, REQ-QUAL-008)

Coverage says a line ran. Mutation says the assertion would have noticed if the line were
wrong. On the scope gate, the proof ladder, the audit chain and the SQL proof helper, "the test
would not notice" is the one answer that is unacceptable — so the same mutants the gate uses in
CI are available to you:

```bash
python -m arachne.fuzz.mutate --list                 # every mutant, no tests run
python -m arachne.fuzz.mutate --sample 12 --check     # the pull-request subset, gated
python -m arachne.fuzz.mutate --check --json          # the full run, gated
```

**It needs the project's interpreter on `PATH`** (`source .venv/bin/activate`). Each mutant is
run in a subprocess with `python -m pytest`; if that `python` cannot import this project the
gate refuses to start and says so, rather than reporting a screen of errored mutants.

**How a mutant is judged.** The module's source is parsed, one node is altered, and the real
test suite runs against the altered module — nothing is stubbed, and the working tree is never
touched. The verdicts:

* **killed** — at least one test failed. The suite noticed.
* **survived** — the run passed. The suite did not notice; this is the finding.
* **timeout** — the mutant hung the suite. Counted as killed: the suite did notice.
* **error** — the mutant could not be collected. Counted as neither: crediting a crash as
  detection would inflate the score. A mutant the loader never managed to install also lands
  here, so a broken gate cannot look like a strong one.
* **allowed** — a curated entry in `[tool.arachne.mutation.allowlist]` in `pyproject.toml`: a
  mutant that is genuinely equivalent to the original, so no test could ever kill it. Every
  entry carries a written reason, and the gate **fails when an entry no longer matches a
  mutant** — an allowlist that only grows is how a gate stops being a gate.

**Responding to a survivor.** A surviving mutant is a test gap, and the fix is a test, not an
allowlist entry. Read the mutant's location, ask what assertion would have failed, and add it.
Allowlisting is for mutants that cannot change behaviour — a `frozen=True` flag, say — and only
with the reason written down.

**Bounded runtime.** `--sample N` takes every k-th mutant deterministically for a pull request;
the nightly job runs the whole set. `--budget-seconds` stops a run and says it stopped early
rather than holding a job open.

