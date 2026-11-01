# Security Assessment Report — target.example

Scan: scan_1 · 2026-10-27 · ARACHNE 0.1.0 (modules M3, M4) · engine: heuristic
Authorization: attested by felix@corp (scope: target.example; expires 2026-11-30T00:00:00+00:00)

## 1. Executive summary

ARACHNE scanned 0 asset(s) — 0 host(s), 0 URL(s) — across M4, M3 over 41 minutes. Overall posture: critical.

The scan confirmed 2 finding(s): 1 critical, 1 high. The most serious is F-000002 · Unauthenticated admin dashboard (CWE-284) on https://target.example/admin (severity critical, confidence 95/100).

Headline findings, in priority order: F-000002 · Unauthenticated admin dashboard (CWE-284) on https://target.example/admin; F-000001 · Sensitive environment file exposed (CWE-200) on https://target.example/.env.

Recommended priority order: Block .env at the web-server layer and rotate the credentials. Each finding in section 4 onward carries its own numbered remediation and a verification-of-fix step.

A further 1 observation(s) fall below the 55 confidence threshold and are reported separately in section 9. They are not confirmed findings and should be triaged before they are acted on.

Analysis was performed by the heuristic engine using template corpus 1.0; every finding cites the evidence that produced it and the rule (or signature) that decided it.

| Severity | Count |
|---|---|
| Critical | 1 |
| High | 1 |
| Medium | 0 |
| Low | 0 |
| Info | 0 |
| **Total** | **2** |

Low-confidence observations (reported separately, not confirmed): 1

## 2. Scope & methodology

- Target definition: target.example
- Modules enabled: M4, M3
- Engine mode: heuristic · analysis corpus narrative-v1
- Timeframe: 2026-10-27T12:00:00+00:00 → 2026-10-27T12:41:00+00:00 (2460 seconds)
- Checks run: 2 run, 1 not run
- Rate limits: global_per_second=20.0, per_host_per_second=5.0
- Report schema: 1.11

**Scope (compiled, deny by default):**

- allowed_hosts: target.example
- excluded_hosts: legacy.target.example

**Exclusions:** legacy.target.example

| Module | Check | Version | Research | Status |
|---|---|---|---|---|
| M4 | env-file-probe | 1.0 | ch04#1 | ran |
| M4 | default-credentials | 1.0 | ch04#26 | not run — not run (opt-in) |
| M3 | security-headers | 1.0 | ch03#35 | ran |

## 3. Asset inventory

No assets were recorded.

## 4. Findings — Critical

### 4.1 F-000002 · Unauthenticated admin dashboard (CWE-284) · conf 95

Asset: https://target.example/admin · CVSS 7.5 · first seen 2026-10-27

**Description:** The file returned HTTP 200 and contained credentials.

Classification: check `m4.dashboard-exposure@1.0` · research `ch04#5` · A01:2021-Broken Access Control

**Evidence:**
- **E-0004 · http_request** — GET https://target.example/admin · sha256 `aaaaaaaaaaaaaaaa…`
  Request: `GET https://target.example/admin`
  Headers: accept: */*; cookie: [REDACTED:value]
- **E-0005 · http_response** — HTTP 200 · 46 bytes · matched patterns: aws-access-key-id · sha256 `bbbbbbbbbbbbbbbb…`
  Response: 200 · 46 bytes · matched patterns: aws-access-key-id
  ```
  AWS_ACCESS_KEY_ID=[REDACTED:aws-access-key-id]
  ```
- **E-0006 · note** — candidate 2 provenance · sha256 `161b1ed38b674bd1…`
  Detail: candidate 2 provenance

**Remediation:** Block .env at the web-server layer and rotate the credentials.

1. Add a deny rule for /.env.
2. Rotate the exposed keys.

**Verification of fix:**
1. Re-request the path; it must return 404.

**References:** <https://cwe.mitre.org/data/definitions/200.html>

**Provenance:** engine=heuristic, template=narrative-v1, rules=exposure.env-file, analysis_log=al_2, status=open, remediation=admin-surface

## 5. Findings — High

### 5.1 F-000001 · Sensitive environment file exposed (CWE-200) · conf 92

Asset: https://target.example/.env · CVSS 7.5 · first seen 2026-10-27

**Description:** The file returned HTTP 200 and contained credentials.

Classification: check `m4.env-file-probe@1.0` · research `ch04#1` · A05:2021-Security Misconfiguration

**Evidence:**
- **E-0001 · http_request** — GET https://target.example/.env · sha256 `aaaaaaaaaaaaaaaa…`
  Request: `GET https://target.example/.env`
  Headers: accept: */*; cookie: [REDACTED:value]
- **E-0002 · http_response** — HTTP 200 · 46 bytes · matched patterns: aws-access-key-id · sha256 `bbbbbbbbbbbbbbbb…`
  Response: 200 · 46 bytes · matched patterns: aws-access-key-id
  ```
  AWS_ACCESS_KEY_ID=[REDACTED:aws-access-key-id]
  ```
- **E-0003 · note** — candidate 1 provenance · sha256 `6370b71e43d43353…`
  Detail: candidate 1 provenance

**Remediation:** Block .env at the web-server layer and rotate the credentials.

1. Add a deny rule for /.env.
2. Rotate the exposed keys.

**Verification of fix:**
1. Re-request the path; it must return 404.

**References:** <https://cwe.mitre.org/data/definitions/200.html>

**Provenance:** engine=heuristic, template=narrative-v1, rules=exposure.env-file, analysis_log=al_1, status=open, remediation=env-file-exposure

## 6. Findings — Medium

No medium findings were confirmed.

## 7. Findings — Low

No low findings were confirmed.

## 8. Findings — Info

No info findings were confirmed.

## 9. Attack paths

A path is a chain of findings on one asset whose stages strictly increase (exposure → credentials → access → execution → impact). Its severity is the **terminal** hop's impact. Hops marked *candidate* were not verified by the analyzer and name the check that would verify them.

### ap-d7ece7c989ca — target.example

- Chain: exposure → impact
- Terminal impact: **critical** (verified)
- Cheapest breaking remediation: fix m4.env-file-probe on https://target.example/.env (verified hop): Block .env at the web-server layer and rotate the credentials. — 2 hop(s) depend on it

| Hop | Stage | Check | Asset | Severity | Verified | Evidence |
|---|---|---|---|---|---|---|
| F-000001 | exposure | m4.env-file-probe | https://target.example/.env | high | yes | E-0001, E-0002, E-0003 |
| F-000002 | impact | m4.dashboard-exposure | https://target.example/admin | critical | yes | E-0004, E-0005, E-0006 |

## 10. Low-confidence observations

These observations are **not confirmed findings**. They fell below the report's confidence threshold and should be triaged before they are acted on.

| Id | Title | Asset | Severity | Confidence | Evidence |
|---|---|---|---|---|---|
| F-000003 | Missing HTTP security headers | https://target.example/ | low | 48 | E-0007, E-0008, E-0009 |

## 11. Patch-gap & exposure (M6)

M6 (AI-era signals) did not run in this scan, so no patch-gap section is reported. An absent section is not a clean result.

## 12. Appendix

### A. Evidence payloads (redacted)

#### E-0001 · http_request · sha256 `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`

GET https://target.example/.env

```json
{
  "headers": {
    "accept": "*/*",
    "cookie": "[REDACTED:value]"
  },
  "method": "GET",
  "url": "https://target.example/.env"
}
```

#### E-0002 · http_response · sha256 `bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`

HTTP 200 · 46 bytes · matched patterns: aws-access-key-id

```json
{
  "body": "AWS_ACCESS_KEY_ID=[REDACTED:aws-access-key-id]",
  "captured_patterns": [
    "aws-access-key-id"
  ],
  "headers": {
    "content-type": "text/plain"
  },
  "status_code": 200
}
```

#### E-0003 · note · sha256 `6370b71e43d43353d3393d2eef1c2e63aabb9afa62e96ea737c10ac3470f0fa5`

candidate 1 provenance

```json
{
  "check": "m4.env-file-probe",
  "detail": "candidate 1 provenance",
  "module": "M4"
}
```

#### E-0004 · http_request · sha256 `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`

GET https://target.example/admin

```json
{
  "headers": {
    "accept": "*/*",
    "cookie": "[REDACTED:value]"
  },
  "method": "GET",
  "url": "https://target.example/admin"
}
```

#### E-0005 · http_response · sha256 `bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`

HTTP 200 · 46 bytes · matched patterns: aws-access-key-id

```json
{
  "body": "AWS_ACCESS_KEY_ID=[REDACTED:aws-access-key-id]",
  "captured_patterns": [
    "aws-access-key-id"
  ],
  "headers": {
    "content-type": "text/plain"
  },
  "status_code": 200
}
```

#### E-0006 · note · sha256 `161b1ed38b674bd1fbf14a283dfb84087fdc60c9d355795e51502fcad85a30ed`

candidate 2 provenance

```json
{
  "check": "m4.env-file-probe",
  "detail": "candidate 2 provenance",
  "module": "M4"
}
```

#### E-0007 · http_request · sha256 `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`

GET https://target.example/

```json
{
  "headers": {
    "accept": "*/*",
    "cookie": "[REDACTED:value]"
  },
  "method": "GET",
  "url": "https://target.example/"
}
```

#### E-0008 · http_response · sha256 `bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`

HTTP 200 · 46 bytes · matched patterns: aws-access-key-id

```json
{
  "body": "AWS_ACCESS_KEY_ID=[REDACTED:aws-access-key-id]",
  "captured_patterns": [
    "aws-access-key-id"
  ],
  "headers": {
    "content-type": "text/plain"
  },
  "status_code": 200
}
```

#### E-0009 · note · sha256 `9f849379fe1b07b206f23f7e2808e1d2a9914a6f0a48a713e328a1fddc62cef3`

candidate 3 provenance

```json
{
  "check": "m4.env-file-probe",
  "detail": "candidate 3 provenance",
  "module": "M4"
}
```

#### E-0010 · http_request · sha256 `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`

GET https://target.example/

```json
{
  "headers": {
    "accept": "*/*",
    "cookie": "[REDACTED:value]"
  },
  "method": "GET",
  "url": "https://target.example/"
}
```

#### E-0011 · http_response · sha256 `bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`

HTTP 200 · 46 bytes · matched patterns: aws-access-key-id

```json
{
  "body": "AWS_ACCESS_KEY_ID=[REDACTED:aws-access-key-id]",
  "captured_patterns": [
    "aws-access-key-id"
  ],
  "headers": {
    "content-type": "text/plain"
  },
  "status_code": 200
}
```

#### E-0012 · note · sha256 `0c81c595bd08e81dae31e09833d70ed2fd6fd67cdcfacf177451be64678ab14c`

candidate 4 provenance

```json
{
  "check": "m4.env-file-probe",
  "detail": "candidate 4 provenance",
  "module": "M4"
}
```

### B. Audit log summary

0 event(s) · 0 blocked · (not recorded) → (not recorded)

### C. Out-of-scope events

No request was refused or discarded for scope reasons.

### D. False positives

| Finding | Title | Status | Reason |
|---|---|---|---|
| F-000004 | Generic server banner | fp | placeholder page |

### F. State changes on targets

No state change was made on any target.

### E. Glossary

- **CAPEC**: Common Attack Pattern Enumerations and Classifications identifier.
- **CVE**: Common Vulnerabilities and Exposures identifier for a known vulnerability.
- **CVSS**: Common Vulnerability Scoring System v3.1 base score (0-10).
- **CWE**: Common Weakness Enumeration identifier for the class of weakness.
- **EPSS**: Exploit Prediction Scoring System probability (0-1), when a feed is available.
- **attestation**: Who authorized the scan, for which scope, and when (F-08-05).
- **confidence**: 0-100 evidence-quality score. Below the report threshold a finding is listed as a low-confidence observation and is not a confirmed finding.
- **redacted**: The captured value was redacted at capture time; placeholders such as [REDACTED] replace any secret.
- **severity**: critical >= 9.0, high >= 7.0, medium >= 4.0, low >= 2.0, otherwise info.

## 13. Simulated scenarios (what-if)

> **Simulated — nothing here was observed on a target**

Nothing in this section was observed on a target. It is a computation over the estate model built from earlier scans, under the hypothetical states listed below.

- Provenance: **simulated**
- Estate model: lab-estate
- Built from scan(s): 1
- Exposure score: 10 → 20

### Hypothetical states injected

| Id | Kind | Asset | Severity | Hypothetical change |
|---|---|---|---|---|
| hyp-1 | new-exposure | legacy.example | high | the legacy console is published by mistake |
| hyp-2 | new-vulnerability | legacy.example | critical | assume the advisory published yesterday is exploitable |
| hyp-3 | applied-fix | app.example | info | rotate the vendor defaults |

### Resulting paths

Each hop is marked *observed* (a scan established it) or *hypothetical* (a hypothesis introduced it, naming which). These paths are **not** findings and are excluded from every gate verdict.

#### ap-4595d4fc86d1 — legacy.example

- Chain: exposure → access → execution
- Terminal impact: **critical** (hypothetical)
- Introduced by: hyp-1, hyp-2
- Cheapest break: fix sim.new-exposure.hyp-1 on legacy.example (hypothetical hop introduced by hyp-1): undo the hypothetical change: Newly exposed surface on legacy.example — 3 hop(s) depend on it

| Stage | Check | Asset | Severity | Origin | Hypothesis |
|---|---|---|---|---|---|
| exposure | sim.new-exposure.hyp-1 | legacy.example | high | hypothetical | hyp-1 |
| access | m2.telnet-service | legacy.example | medium | observed | — |
| execution | sim.new-vulnerability.hyp-2 | legacy.example | critical | hypothetical | hyp-2 |

#### ap-df8afa716490 — app.example

- Chain: exposure → execution
- Terminal impact: **critical** (observed)
- Cheapest break: fix m4.env-file-probe on https://app.example/.env (verified hop): remediate Exposed environment file — 2 hop(s) depend on it

| Stage | Check | Asset | Severity | Origin | Hypothesis |
|---|---|---|---|---|---|
| exposure | m4.env-file-probe | https://app.example/.env | high | observed | — |
| execution | m3.sqli-oracle | https://app.example/login | critical | observed | — |

### Proposed change: publish-legacy-console

Publish the legacy admin console on 8443 and assume the newly published advisory is exploitable, while the default-credential finding is closed.

- Exposure before: 10 (1 path(s))
- Exposure after: 20 (2 path(s))
- Delta: **+10** (worse)
- Paths introduced: ap-4595d4fc86d1, ap-df8afa716490
- Paths removed: ap-e7bfc2ce2f4f
