# ADR 150 — Stage 10: M3 extended families + M5 cloud/container/supply chain

> **Owner:** ARACHNE architecture group · **Last verified:** 2026-11-05 · **Review interval:** 1825 days

- **Status:** accepted
- **Date:** 2026-10-29
- **Superseded in part by:** [ADR 350](350-native-image-scanning-and-declared-cloud-breadth.md)
  for the container-image decision. What this record describes as "the external image scanner
  (`ARACHNE_M5_REGISTRY_SCAN` / `ARACHNE_M5_SBOM_TOOL`), off by default" became a **native,
  on-by-default** layer scanner, with the external Trivy/Grype path kept as an opt-in import of
  a report produced out of band. The rest of this record — the M3 families and the M5 cloud
  posture — still stands. The decisions below are left as written rather than edited: a decision
  record says what was decided at the time, and the superseding record is how the change is
  traced.
- **Scope:** S10 (roadmap phase 3). Adds the remaining M3 web-application families and the whole
 M5 module (M3/M5, F-02-04/F-02-06), with rules, narratives, remediation, CVSS
  vectors, the planning catalogue, the coverage matrix and two new lab fixtures.

## Context

S6 built twelve M3 core checks and S7 built twenty-three M4 checks. S10 is the rest of the
web-application corpus plus the cloud/container/supply-chain module: 18 M3 families and 16 M5
checks. It is the stage that first needs *something other than the target's web surface* — a
callback service on ARACHNE's own infrastructure, a local repository clone, a cloud endpoint, a
container registry — and the first that spans CWEs (SSRF, deserialization, supply chain) whose
evidence is a *posture* rather than a response body.

## Decisions

### ADR-S10.1 — One check per spec id; `research_ref` follows 's table for the extended set

The 18 new M3 check ids are exactly 's (`m3.ssrf-probe`, `m3.ssti-oracle`...);
their `research_ref` values are the spec table's corpus references (`ch03#5`, `ch03#6`, ...).
For this set the spec table and the numbered methods in `docs/research/03-web-application-testing.md` agree, so no
reconciliation is needed (unlike M1/M2/M4, ADR-070.3/080.3/120.2). The M5 ids and refs follow
the same rule; two checks carry a **range** (`m5.tfstate-exposure` = `ch05#11-12` for the state
file + IaC review, `m5.k8s-exposure` = `ch05#13-14` for RBAC/API + kubelet/dashboard) because the
spec pairs them and the coverage matrix expands a range to every method it names.

### ADR-S10.2 — The M3 safety contract is unchanged: detection-only, differential, opt-in

Every extended family obeys S6's rules. New in S10 is one more deployment switch:
`m3.ssrf-probe` is the first M3 check that reaches a service **other than the target**, so it is
`enabled_by_default=False`, behind the active-checks gate, *and* behind
`ARACHNE_WEB_SSRF_PROBE`. It sends nothing unless `ARACHNE_WEB_SSRF_CALLBACK` names a service on
ARACHNE's own infrastructure. The probe injects `<callback>/<nonce>` and confirms either the
sink reflected the callback's body (in-band) or the callback recorded the nonce (out-of-band).
The callback service exposes a bounded `/hits` listing the check reads through the same scoped
client, so the lookup is rate-limited and audited like every other request. Loopback callbacks
work in tests; a real deployment points the base at its own collaborator.

### ADR-S10.3 — M5 is read-only and local-first; the switches are the safety contract

M5's checks are `passive`/`hybrid`/`active` exactly as the spec's type column says, and the two
metadata families (`m5.imds-ssrf`, `m5.azure-mi-audit`) are `enabled_by_default=False` **and**
behind `ARACHNE_M5_IMDS_PROBE` on top of the active-checks gate. Three more deployment switches
exist because the action is a deployment decision, not a scan decision:

- `ARACHNE_M5_VALIDATE_CLOUD_KEYS` — the read-only `sts:GetCallerIdentity` validation of a key
  `m5.leaked-cloud-keys` found. Off by default; the documented permission list is the corpus's
  `iam/read_only_permissions` (the STS call needs no IAM permission beyond the caller's own
  identity). The SigV4 helper is in `m5/cloud.py`; with the switch off the finding records
  `validation: "not-attempted"`.
- `ARACHNE_M5_REGISTRY_SCAN` / `ARACHNE_M5_SBOM_TOOL` — the external image scanner
  (Trivy/Syft/Grype class). Off by default, so the built-in registry-ACL and offline lockfile
  review work with nothing installed.
- `ARACHNE_M5_DOCKER_SOCKET` — whether `m5.docker-socket` also looks for a local socket artifact.

Repository/pipeline analysis reads a **local clone only** (`repo:<path>` / `file://<path>` /
a bare path). A remote `git@host:org/repo` or `https://github.com/...` target has no clone in a
scan; the check reports itself *skipped* rather than cloning. This is the M5
safety text ("runs on local clones only") made mechanical.

### ADR-S10.4 — Request smuggling is a framing-boundary audit, not a desync exploit

`m3.smuggling-oracle` cannot emit the invalid framing a true CL.TE/TE.CL probe needs: the shared
client is the only egress path (ADR-05), and its HTTP library refuses `Transfer-Encoding` values
other than `chunked` before they leave the process (`LocalProtocolError`). Rather than weaken
the single-egress invariant, the check performs a **framing-boundary audit**: it reports an
endpoint whose response carries a proxy hop (`Via`/`X-Backend-Server`) in front of a distinct
origin `Server` — the two-parser topology a desync requires — as a low-confidence
`request-smuggling` signal for manual validation, and it never claims a confirmed desync. The
artifact records `confirmed_desync: false`. This is a deliberate, documented limitation; a
future stage that adds a raw-framing capability to the net client can turn it into an active
probe without changing the check id, rule or narrative.

### ADR-S10.5 — Body redaction forces the JWT oracle to be honest about what it can see

The HTTP client redacts a JWT at capture time (the `jwt` detector), so a check can never obtain
a token from a response body to decode or crack. `m3.jwt-audit` therefore does two things it
*can* do: it reports a client-delivered JWT as an exposure (the detector fired on the asset —
the token is public to anyone who loads the page), and it audits the one token the scan is
allowed to hold — the operator's env-configured session token — offline (alg-none, weak-HMAC
secret). It never forges or replays a token from the target. A DOM/client-side token-cracking
check would need a configured *sample* token, which is an operator decision, not a scanner
default.

### ADR-S10.6 — Prototype pollution is server-observable only; DOM-sink verification is out of scope

A real client-side prototype-pollution oracle needs a headless browser to observe property
inheritance, and S6 already deferred DOM-sink verification (ADR-100.4). `m3.proto-pollution`
sends a benign `__proto__`/`constructor.prototype` marker through a JSON body the server merges
and reports the marker the **server echoed** — a genuine server-side pollution oracle — with no
browser and no gadget chaining. The narrative and remediation say so.

### ADR-S10.7 — The rules key on the artifact signal, and severity is the rule's verdict

Every S10 check attaches one machine-readable `artifact` whose `signal` names the oracle. The 38
new rules key on `evidence.artifact.signal == "<signal>"` plus at most one differentiating fact
(`in_band`, `validated`, `plaintext_secrets`, `cacheable`, `wildcard`, ...), and the rule's
`severity_if` clause is the verdict. Two checks own more than one rule because they report two
distinct root causes: `m5.tfstate-exposure` (state-file exposure + IaC misconfiguration) and
`m5.k8s-exposure` (kubelet + dashboard), `m5.docker-socket` (API + socket artifact),
`m5.image-history-secrets` (secret material + root user). Remediation ids are unique per
remediation, not per check, so the two docker/k8s entries are split.

### ADR-S10.8 — New CWEs are managed data, added with their entries

The extended families need 16 CWEs that were not in the S5 vector table (1336, 611, 444, 347,
235, 1321, 362, 915, 840, 1385, 350, 312, 1104, 269, 427, 1116, 250). Each was added with a
CVSS v3.1 base attribute set and a remediation entry in the same commit, because
`tests/unit/test_rules.py` fails the build if a rule's CWE has no vector or its remediation id
does not resolve. The CWE→OWASP map falls back to its default category for a CWE it does not
name, which is the documented behaviour (S8 ADR-130.x), so no report QA change was needed.

### ADR-S10.9 — Two lab fixtures, not one

The M3 extended families run against the existing stdlib web lab, extended with the
Juice-Shop-class advanced scenarios (`tests/lab/web_lab.py`: `/ssti`, `/xxe`, `/ping`, `/deser`,
`/smuggle`, `/cache-me`, `/hpp`, `/api/profile`, `/merge`, `/graphql`, `/ws`, `/checkout`,
`/redeem`, `/oauth/authorize`, `/saml/acs`, a weak-secret JWT in `/app.js`, a GitHub-Pages
takeover fingerprint, and hardened counterparts). M5 needs a different surface — cloud endpoints
and a repository — so it gets `tests/lab/cloud_lab.py` (S3/MinIO, Firebase, Supabase/PostgREST,
a Terraform backend, kubelet, Docker daemon, OCI registry, an IMDS sink) and
`tests/fixtures/repo/` (a risky GitHub Actions workflow, a committed `.tfstate`, open IaC, a
Dockerfile with an ENV secret and `USER root`, plaintext Helm values, internal-scoped
dependencies, a vulnerable lockfile, a GCP service-account key, a wildcard IAM policy, a `.env`).
The two fixtures are independent because the surface is: a scan can have either without the
other.

### ADR-S10.10 — The acceptance tests score the finding set per check

`tests/integration/test_m3x_scan.py` and `tests/integration/test_m5_scan.py` drive each check
directly over the shared crawl/client (as the checks step would) and assert a planted signal
appears in the candidate's evidence, then print the finding set. This is the S10 "extended lab
coverage recorded" criterion. The S6/S7 acceptance suites already prove the full pipeline, so
S10 does not re-run the orchestrator for every new check; the opt-in gates are asserted directly
(the SSRF switch off, the IMDS switch off) as well as the hardened-control false positives.

### ADR-S10.11 — M5 runs in the `checks` step and shares M3/M4's egress and evidence shape

All M5 checks map to `ScanStep.CHECKS` (the existing `MODULE_STEP` table), so the checks
handler's shared crawl feeds `m5.imds-ssrf`/`m5.azure-mi-audit` the same `ctx.web` it feeds M3,
and every endpoint check uses M3's `fetch`/`safe_fetch` and `web_candidate` (request, response,
artifact). Artifact checks read the local clone and run with no HTTP client at all, which is why
they work in a scan that declared no URL asset. No pipeline step or handler change was needed
beyond registering the M5 group.

## Consequences

- The registry grows from 61 to 95 checks (M3 12→30, M5 0→16); 8 are opt-in and 53 are active.
- The coverage matrix grows from `70/175` to a higher count once regenerated; the M3/M5 rows now
  come from the implemented checks rather than placeholders.
- A future raw-framing capability in the net client can upgrade ADR-S10.4's audit without a
  check-id change; a configured sample token can upgrade ADR-S10.5 the same way.
- The two lab fixtures are reusable by S11 (M6) and S13 (performance/FP tuning).
