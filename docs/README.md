# ARACHNE documentation

Everything you need to run, operate, extend or review ARACHNE. Pick the row that describes
you.

---

## If you want to **use** ARACHNE

| Document | Read it for |
|---|---|
| [getting-started.md](getting-started.md) | **Start here.** Install, migrate the database, run your first scan, start the API. |
| [operator-guide.md](operator-guide.md) | The reference: every environment variable, every command, every runbook, with troubleshooting. |
| [release-notes.md](release-notes.md) | What is in the current release — and its **known limitations**. Read this before you deploy anywhere that matters. |
| [ci-integration.md](ci-integration.md) | Using ARACHNE as a CI gate: exit codes, thresholds, and wiring for GitHub Actions and GitLab. |
| [security.txt](security.txt) | RFC 9116 security policy: how to report a vulnerability in ARACHNE itself. |

**The one-paragraph orientation.** ARACHNE is a defensive vulnerability scanner. It inspects
targets you are authorized to test, proves what it finds through a graduated safe proof
ladder (read-only by default; anything stronger is opt-in, attested, audited and restored),
and produces evidence-backed reports. It runs on a deterministic heuristic engine, a
pluggable AI engine, or both. Scope is deny-by-default, every request is validated against
it before it is sent, and the audit trail is hash-chained.

---

## If you want to **extend** ARACHNE

| Document | Read it for |
|---|---|
| [plugin-developer-guide.md](plugin-developer-guide.md) | The check contract: metadata field rules, proof levels, evidence, the registry, and packaging a plugin. Two complete worked examples ship with the project. |
| [architecture.md](architecture.md) | How the system fits together: the scan pipeline, the safety stack, the dual engine, distributed mode — with diagrams. |
| [adr/](adr/) | Why it is built this way. One decision record per build milestone, including the alternatives that were rejected. |
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | How to contribute: code standards, the test layers, the Definition of Done, commit and PR conventions. |

---

## If you are **reviewing or auditing** ARACHNE

| Document | Read it for |
|---|---|
| [security-review.md](security-review.md) | A line-by-line review of the codebase against its own security requirements, with a finding register and the fixes applied. Open findings are marked as such. |
| [external-pentest-report.md](external-pentest-report.md) | The external penetration-test report: methodology, scope and findings register. |
| [reproducible-builds.md](reproducible-builds.md) | Reproducible builds, the SBOM, signing and provenance — what is deterministic and what is not. |
| [scim-ldap-interface.md](scim-ldap-interface.md) | The identity-provisioning interface design for SCIM and LDAP. |

---

## Responsible use

ARACHNE only scans targets the operator is **authorized** to test. Scope is deny-by-default,
every refusal is audited, and the tool contains no exploitation, persistence or destructive
capability by design.

- The reporting policy for vulnerabilities **in ARACHNE** is [../SECURITY.md](../SECURITY.md).
- The terms are [../LICENSE](../LICENSE).
- The operator-facing responsible-use statement is at the top of [../README.md](../README.md).

---

## How this documentation is organised

- **`docs/`** is documentation for the **shipped product** — what an operator, an integrator
  or a reviewer needs.
- **`docs/adr/`** records *why* the product is the way it is, one decision per milestone.
- The project's own build-time notes are not part of the shipped documentation; they are
  removed from the repository before a release.

Every page here is expected to match the code it describes. If a path, a command or a number
in these pages does not match what the code does, that is a bug — please report it.
