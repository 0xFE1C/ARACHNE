# Chapter 6 — Vulnerability Correlation, Threat Detection and Adversary Emulation

> **Owner:** Detection group · **Last verified:** 2026-11-05 · **Review interval:** 365 days

The M6 surface. The first half correlates what the other modules observed against
vulnerability, exploit and threat data to answer "does this matter, and is anyone using it".
The second half is detection engineering: reading the target's own telemetry rules and
post-exploitation indicators, and validating them with a controlled, non-destructive
emulation. Method 13 is deliberately not implemented: autonomous agentic exploitation is the
capability this tool exists to refuse.

## Case studies

Two case studies explain why parts of M6 are shaped the way they are. They are the reason two
checks combine a signature with a behaviour, and why the exploitation view is EPSS-weighted
rather than CVSS-weighted.

**(a) PHP2SHELL — the patch-to-exploit window.** A pair of RCE CVEs (CVE-2026-109618 and
CVE-2026-109619) went from patch to observed exploitation in **hours**, with a
patch-to-disclosure window of four days. Two consequences follow, and both are implemented:

- The first exploitation of an embargoed RCE *precedes* CVE-specific signatures, so
  `m6.webshell-yara` (method 24) matches behaviour — oversized single lines, encoded blocks,
  eval-heavy code, anomalous file timestamps — as well as markers. A signature-only check
  detects this class too late to be useful.
- CVSS alone would not have raised the pair above routine patching. `m6.cve-epss-correlation`
  (method 7) ranks by EPSS and known-exploited status for exactly this reason.

**(b) Kerberoasting over a long tail of shares.** The Sigma rule set (methods 18–23) was
written against a real intrusion that moved laterally over ordinary file shares rather than
through a named exploit: nothing in it is a CVE, and no version-based correlation would have
seen it. That is why the M6 surface is telemetry-shaped and not only vulnerability-shaped.

## Methods

### 1. Vulnerability database ingestion

Normalising CVE, CWE and vendor advisory feeds into one store with a stable identity and a
recorded provenance. Not implemented: feed ingestion is planned, and the current checks read
the bundled catalogue instead.

### 2. Exploit-availability indexing

Tracking which vulnerabilities have public proof-of-concept code or a weaponised module, as a
prioritisation signal. Not implemented: the tool must not ship or fetch exploit code, and the
prioritisation signal is taken from EPSS and known-exploited lists instead.

### 3. Template-driven signature scanning

Running a declarative template vocabulary (request, matcher, extractor) against a scoped
target, which is how new signatures are added without new Python. Read-only templates only;
templates that write are rejected at load time.

### 4. Known-exploited-vulnerability prioritisation

Raising the CVEs that appear on a known-exploited list, which is a stronger signal than
severity alone. Not implemented: the list is ingested as data in method 1's pipeline.

### 5. Exploit-to-finding matching

Joining an observed product and version against the exploit-availability index to say which
findings have a public path. Matching is on version evidence; nothing is executed.

### 6. Patch-level correlation

Comparing the observed version against the fixed version rather than the affected range, to
avoid the false positives a bare version-range join produces. Not implemented: the catalogue
carries affected ranges only.

### 7. EPSS and CVE correlation

Weighting a CVE by its EPSS probability and its recency, so the queue is ordered by
likelihood of exploitation rather than by CVSS alone.

### 8. At-scale secret scanning

Scanning a repository set, a bucket or an image corpus for credential patterns, with the
entity-resolution step that keeps one leaked key from becoming two hundred findings.

### 9. Supply-chain provenance verification

Checking that a build artefact carries verifiable provenance and that the provenance names
the expected source and builder. Not implemented: it needs a signed-attestation verifier the
release surface will add.

### 10. Threat-actor campaign attribution

Mapping observed indicators onto tracked campaigns and their tooling. Not implemented: it
needs a commercial or community intelligence feed the tool does not bundle.

### 11. Dark-web and leak-site monitoring

Watching criminal marketplaces and leak sites for organisation identifiers. Not implemented:
it needs a commercial feed, and it is a monitoring service rather than a scan.

### 12. Honeypot and decoy deployment

Placing a decoy service so that an interaction with it is itself the signal. Not implemented:
deploying a listener into a target estate is a state change the proof ladder does not
sanction for this tool. The passive half is method 25.

### 13. Autonomous agentic exploitation

An agent that plans and executes an intrusion end to end. **Not implemented, deliberately.**
This is the capability ARACHNE is built to refuse: it is offensive, it is unauditable at the
point of action, and its proof value is lower than the read-only alternatives above.

### 14. GenAI application attack-surface mapping

Enumerating the LLM-backed surface: chat endpoints, retrieval routes, tool/function
definitions, vector stores and the model provider in use.

### 15. LLM prompt-injection surface mapping

Mapping where untrusted content reaches a model prompt (retrieved documents, user fields,
tool output) and whether the application separates instructions from data.

### 16. Local privilege-escalation discovery

Enumerating the local misconfigurations that allow a low-privilege account to gain more:
sudoers entries, setuid binaries, scheduled tasks, service binary paths, writable service
directories and unquoted paths. Enumeration only: no privilege is obtained.

### 17. Credential store hunting

Locating credential material on a host or in an estate (browser stores, cloud CLI caches,
`~/.ssh`, `~/.aws`, configuration files, environment of long-running processes) to establish
what an intruder would find. The credential's value is never used or disclosed.

### 18. Sigma hunt-rule evaluation

Reading the target's detection rules, translating the ones the tool can evaluate, and running
them against supplied telemetry to find the rules that would not have fired.

### 19. Active Directory attack-path analysis

Reading group membership, ACLs, delegation and trust configuration to compute the shortest
path an attacker would take to a privileged principal. Analysis of the directory's own
structure; no ticket is requested and no session is opened.

### 20. Detection-rule coverage assessment

Mapping the estate's rules onto a technique vocabulary, to name the techniques with no
detection at all.

### 21. Log-source telemetry review

Checking that the log sources the rules depend on are actually collected, parsed and
retained for long enough to be useful.

### 22. Purple-team detection validation

Executing a controlled, non-destructive emulation of a technique and checking whether the
estate's own telemetry recorded it. Nothing is dropped, persisted or exfiltrated.

### 23. CI pipeline secret-leak detection

Watching pipeline definitions and their history for credentials committed to a workflow file
or printed to a job log.

### 24. Webshell signature scanning

Matching known webshell families with YARA signatures over file content, including the
obfuscated and polymorphic variants a hash-based check misses. File content is read, never
executed.

### 25. Deception listener observation

Reading the interactions a decoy listener recorded, which turns a passive observation into a
high-confidence signal. The listener is deployed by the operator, not by the scanner.
