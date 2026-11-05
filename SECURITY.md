# Vulnerability disclosure policy (VDP)

> **Owner:** Trust group · **Last verified:** 2026-11-05 · **Review interval:** 180 days

*ARACHNE external-validation artifact (REQ-TRUST-007). Review at every major release.*

This document is ARACHNE's **vulnerability disclosure policy**. It says what the project
will accept a report about, how to send one, and what the reporter can expect in return.
It is a companion to [`docs/security-review.md`](docs/security-review.md) (the internal
review of this codebase) and to the published external penetration-test report
[`docs/external-pentest-report.md`](docs/external-pentest-report.md). It does not
contradict either: the review's own finding labels (`F1`...`F9`) and its process stay
where they are, and the disclosure timeline below is the one that applies to reports
arriving *from outside* the project.

## What ARACHNE is (read this first)

ARACHNE is a **defensive security tool**: it detects and reports vulnerabilities in
targets the operator owns or is explicitly authorized to test. It detects — it does not
exploit, weaponize, or maintain access. Its hard non-goals are stated in the [README](README.md) and enforced in code
(deny-by-default scope and authorization gates, the proof ladder, no persistence). Using
ARACHNE against systems **without authorization is prohibited** and is contrary to the
product's own design: the license and the mandatory authorization attestation make an
unauthorized scan a refused, audited operation, not a supported one. A report that
amounts to "I pointed ARACHNE at a system I do not own" is not a vulnerability in
ARACHNE.

## Scope

In scope:

* The ARACHNE source code in this repository (`src/arachne/**`, the tests, the CLI, the
  API and web UI, the agent, the plugin/content-pack loaders, the report renderers).
* The container images **published by this project**, and the Helm chart shipped in
  `deploy/helm/`.
* The tool's own **safety invariants** when they can be defeated: a way to make ARACHNE
  contact a host outside its declared scope, bypass the authorization attestation,
  escalate a proof level without the required approval, or send outside an attested
  purple/detection window is a high-value finding and is explicitly in scope.

Out of scope (report elsewhere or not at all):

* **Third-party dependencies.** Report those upstream to the affected project. ARACHNE
  ships a CycloneDX SBOM (`python -m arachne.tools.sbom`) and `pip-audit` runs as a
  release gate, so a dependency advisory is tracked there; it is not an ARACHNE
  vulnerability report.
* **The target systems ARACHNE scans.** Those belong to the operator who declared them,
  and testing them without authorization is prohibited (above).
* **Social engineering, phishing, or physical attacks** against project maintainers,
  contributors or infrastructure.
* **Denial of service, resource exhaustion, or automated high-volume fuzzing** against
  project infrastructure. ARACHNE's own non-goals forbid these against *targets*; they
  are equally unwelcome against the project itself.
* Findings that require a deliberately misconfigured deployment that contradicts the
  shipped defaults and the operator guide (for example, a deployment that turns off the
  scope gate and then complains it has no scope gate).

## How to report

Open a **GitHub Security Advisory** (private by default) via the repository's *Security*
tab → *Report a vulnerability*, or directly at:

```text
https://github.com/0xFE1C/ARACHNE/security/advisories/new
```

The advisory form is the primary channel and the one named in
[`docs/security.txt`](docs/security.txt); the maintainer ([@0xFE1C](https://github.com/0xFE1C))
is notified for every submission.

Please do **not** open a public issue for a security report before it has been triaged.

## What to include

A useful report contains, where applicable:

* The ARACHNE version, the commit or image digest, and how it was deployed (CLI, API,
  container, Helm chart).
* The affected component and the reproduction steps, in as small a form as possible.
* The observed versus expected behaviour, and the security impact as you understand it.
* A proof of concept (requests, inputs, a trace) — the minimum needed to demonstrate the
  issue. Do not exfiltrate data, do not disrupt services, and do not access anything that
  is not yours to access.
* Your assessment of severity, ideally with a CVSS v3.1 vector.
* How you would like to be credited, or a request to remain anonymous.

## Our commitments

| Stage | Window |
|---|---|
| Acknowledgement of your report | 3 business days |
| Initial triage and severity assessment | 10 business days |
| Coordinated disclosure | 90 days from acknowledgement by default |
| Status updates | at least every 30 days until resolution |

The 90-day disclosure window is the default, not a gag: it may be shortened by agreement
(for example, if a fix ships sooner) or, exceptionally, extended if a fix requires
coordinated upstream work — we will tell you why and agree the new date with you rather
than let it pass in silence. We will keep you informed if a report is accepted, disputed,
or found to be out of scope.

## Credit policy

We credit reporters who ask to be credited, by name or handle as you prefer, in the
release notes and in the acknowledgements page referenced from `security.txt`. We do not
currently run a paid bounty program; the acknowledgement is the credit. If you prefer to
remain anonymous, we will respect that and credit the report as "an anonymous reporter".

## Safe harbour

We consider security research conducted in good faith — under this policy, against
systems you own or are authorized to test, without disruption, data exfiltration, or
social engineering — to be authorized activity, and we will not pursue or support legal
action against researchers who comply with it. If a third party brings a claim against
you for research that followed this policy, we will make it clear that your actions were
considered authorized. This safe harbour does not extend to activity that is illegal
independently of this policy, nor to testing of systems you are not authorized to test.

## Encrypted reporting

Please **encrypt** sensitive reports where possible. The maintainer response will
include the current PGP public key fingerprint on request; do not send a full technical
report in clear text before you have it. A GitHub Security Advisory is transported
inside GitHub's own access controls and may be used when PGP is not practical.

## Artifacts

This policy is published alongside the project's other external-validation artifacts,
all shipped in this repository and present at the release gate:

| Artifact | Path | Purpose |
|---|---|---|
| Vulnerability disclosure policy (this document) | `SECURITY.md` | Scope, reporting, commitments, safe harbour |
| `security.txt` (RFC 9116) | `docs/security.txt`, served at `/.well-known/security.txt` | Machine-readable contact and policy pointer |
| External penetration-test report | `docs/external-pentest-report.md` | Methodology, findings register, remediation SLA — updated per major release |
| Security review of the codebase | `docs/security-review.md` | The internal review behind the posture above |

The machine-readable `security.txt` is the entry point a scanner (or a researcher) finds
first; it points back at this policy and at the penetration-test report's publication
process. The report placeholder is replaced by the commissioned report at the next major
release; until a test has actually been run, its findings register is empty and no
security claim is made from that emptiness.
