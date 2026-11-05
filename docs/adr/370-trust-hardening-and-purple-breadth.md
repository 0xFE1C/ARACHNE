# ADR-370 · Trust hardening and purple breadth: an asymmetric deployment key, generated compliance maps, and a 36-technique ATT&CK v20 catalogue

> **Owner:** ARACHNE architecture group · **Last verified:** 2026-11-05 · **Review interval:** 1825 days

| Field | Value |
|---|---|
| Status | accepted (WP-19) |
| Date | 2026-11-05 |
| Deciders | ARACHNE trust owner, detection engineering, compliance owner |
| Extends | ADR-300.5 (the HMAC limitation this closes); ADR-290 (the purple catalogue this grows); ADR-04 (the framework maps, now generated) |
| Requirements | REQ-TRUST-008, REQ-TRUST-009, REQ-TRUST-010, REQ-TRUST-011, REQ-VALID-007 |

## Context

Three controls were honest but thin, and one was a recorded limitation:

1. **Every verifier could forge.** The audit chain, the row signatures and the scan seals are
   HMAC-SHA256 under the deployment key, so the party that verifies is the party that can make
   a signature. ADR-300.5 named it: "an auditor who must not be able to forge cannot verify".
   A third-party attestation is impossible under a symmetric key, which is the one thing a
   trust feature has to get right.
2. **The compliance maps were thin and hand-maintained.** CIS 16 of 153 safeguards, ISO 16 of
   93 Annex A controls, CSF 12 of 106 subcategories, PCI 10 of 12 requirements. The mechanism
   was sound (no dangling ids, the framework's total stated) but the volume was 10–17% and the
   maps were a second, parallel source that could drift from the check catalogue.
3. **The purple catalogue covered three ATT&CK techniques** against MITRE's in-scope 65. The
   mechanism was right — replay a declared proof payload and score what the defender saw — with
   almost no content, and its tactic vocabulary was v14-era (14 tactics, "Defense Evasion").
4. **The benchmark published aggregates only**, so "94% detection" could not be reproduced
   case-by-case, and nothing recorded the command, environment or corpus version that produced
   it. Release provenance was SLSA-*style* rather than a stated SLSA version, and the SBOM was
   CycloneDX by construction but never validated against the schema it claims.

## Decision

### 370.1 Ed25519 alongside HMAC, with an unchanged signature format

The deployment key gains a second scheme. `Ed25519Signer` signs with a 32-byte seed and
verifies with a 32-byte public key; an instance holding **only** the public key is a legal,
useful state — it verifies every signature the holder of the seed made and has no code path
that could make one (`sign()` refuses, and there is no derivation from public to private).
That is the requirement, and a verifier that *can* forge fails it.

The primitive is implemented in `core/ed25519.py` in pure Python (RFC 8032: one curve, one
hash, no ASN.1, no parameter negotiation) for the same reason the mTLS fingerprint and the
throwaway client certificate are hand-rolled (ADR-240.5): the runtime dependency set has no
cryptography library, deliberately (ADR-300.5), and the package must work in an air-gapped
install. Correctness is not argued, it is measured: `tests/unit/test_ed25519.py` replays the
published **RFC 8032 §7.1** vectors (seed → public key → exact signature bytes, including the
1023-byte message case) and, when the optional `cryptography` wheel happens to be present as a
developer dependency, cross-checks in both directions. **Known limitation, stated:** the
implementation is not constant-time. Scalar multiplication is square-and-multiply over Python
integers, and CPython makes no timing guarantees. That is irrelevant to the threat this control
addresses (an auditor verifying a stored chain, on the machine holding the key) but a
deployment whose threat model includes a local timing attacker must keep the private key off the
scanning host — the operator guide says so rather than implying the code solves it.

The **format does not break**: a signature is still three colon-separated fields,
`<scheme>:<key id>:<hex>`. HMAC keeps being minted under its historical tag `v1` (so a stored
row's bytes are unchanged and an older reader still verifies a newer writer), `hmac-sha256` is
accepted as the explicit spelling, and Ed25519 carries `ed25519`. Purposes remain mixed into the
signed message by one shared `purpose_message()` for both schemes, so a scheme change cannot
re-open a cross-purpose replay.

**The dual period.** A deployment migrating sets `ARACHNE_INTEGRITY_ALGORITHM=ed25519` *and*
keeps `ARACHNE_INTEGRITY_KEY` set: new rows sign with Ed25519, `build_verifier()` keeps the HMAC
key in its ring, and every row and anchor written before the switch still verifies. The old key
can be dropped once the retention window has passed every pre-switch row. `arachne verify-chain`
verifies through that ring, so the cutover is a retention decision, not a flag day — and
`tests/unit/test_integrity_chain.py` exercises it from both sides.

### 370.2 The compliance maps are generated from check metadata

Each check now declares `CheckMetadata.compliance` — the compliance controls its evidence bears
on (`CIS-3.3`, `ISO-A.8.5`, `CSF-PR.AA-05`, `PCI-6`) — validated at import against a **pinned,
complete inventory** of each framework. `python -m arachne.tools.compliance --write` inverts that
declaration into the four published map files, and `--check` fails when a committed map and the
registry disagree, so "generated, not maintained" is a gate rather than a promise. A check that
gains or loses a control changes the map in the same commit.

The inventories ship in the package (`data/compliance/*.json`), each recording its source, the
retrieval date, the cross-check performed and any uncertainty. Provenance is not uniform and is
not presented as if it were: CIS v8.1 comes from **CIS's own OSCAL publication** (153
safeguards, all 18 group titles cross-checked against CIS's published list), NIST CSF 2.0 from
the **official NIST CSWP 29 PDF** (106 subcategories, function counts 31/21/22/11/13/8), PCI
DSS v4.0's 12 requirement headings from the **official PCI SSC PDF** (via the Internet Archive
capture of the gated URL), and ISO/IEC 27001:2022 Annex A from a **widely used open-source
library cross-checked against a second independent dataset** — the standard is paywalled, no
primary text was downloaded, and the file says so. That last one is a known evidence gap: the
ids and titles are high-confidence and internally consistent, but a licensed copy should be
diffed before anyone treats the file as an audited denominator.

Because each inventory is complete, the map carries the complement explicitly: every control no
check maps onto is listed in `outside_assessed_set` **with a reason** drawn from its group
(organisational, physical, a people control, an operator capability), and the load-bearing
invariant is `assessed + outside == the framework's total` — a control cannot be omitted, only
named. That is what makes the assessed set impossible to mistake for the whole framework.

**Reached: CIS 64/153, ISO 46/93, CSF 42/106, PCI 11/12.** The first three clear the
requirement's targets. The fourth does not, and the reason is not effort: **PCI DSS requirement
9** restricts *physical* access to cardholder data (facility entry, visitor management, media
handling, point-of-interaction tamper protection). No ARACHNE check produces an artefact for any
of it — the scanner is a network instrument with no physical or host-agent sensor — and mapping
it to an exposed-datastore check would tell an auditor a control had been assessed when it had
not. So requirement 9 is reported as `outside_assessed_set` with that reason and the shortfall
is named; `tests/unit/test_compliance_map.py` pins it, and notices if a future check makes it
assessable. **Recorded for change control:** the requirement's "12 of 12" is unreachable without
that false claim.

### 370.3 The purple catalogue is 36 techniques across 10 v20 tactics

The catalogue grows from 7 actions / 3 techniques to **41 actions / 36 techniques / 10 tactics**,
all of them replaying an existing proof-ladder action against a registered check at the check's
own declared level (the planner refuses a map that disagrees). It adds no capability: each entry
names the telemetry the action already produces.

The vocabulary is **ATT&CK Enterprise v20** and it is *read from the pinned snapshot* rather
than kept as a list: `attack-enterprise-v20.json` now carries the release's complete technique
set (706 techniques, 479 sub-techniques) and its 15 tactics, so a technique id is validated
against the release it names — not against a number band — and the action's tactic must be one
the release assigns that technique. Two consequences worth stating: `defense-evasion` is gone
(v20 split it into **Stealth** and **Defense Impairment**, both of which the catalogue now
uses), and **no action is filed under Stealth** — ARACHNE's tests are designed to be seen, and
filing one there would describe an evasion capability the product refuses to have. (ATT&CK
assigns T1078 Valid Accounts Stealth among four tactics; the actions use its
initial-access/persistence assignment for a plain logon test.) The validation is in the *loader*,
not only in a test, so an operator's own map is held to the same rule.

### 370.4 The benchmark and the supply chain state their method

The committed benchmark artefact now carries the corpus version and its digest, the exact
command, the environment (interpreter, platform, build epoch) and **raw per-case rows** with
precision, recall and a per-case time-to-finding whose source is named. Fixture rotation has a
recorded `review_by` date and a test fails when a suite is overdue. Local provenance is emitted
as a SLSA v1.2 in-toto statement by a shipped, offline tool — and it says plainly that it is
*not* SLSA Build L3: L3's non-forgeable provenance comes from the GitHub-hosted build platform
and `actions/attest-build-provenance`, which the release workflow runs and then verifies with
cosign. The SBOM is validated against the vendored official CycloneDX 1.5 schema as part of the
release step, not assumed.

## Consequences

* An auditor with the public key verifies a chain and cannot fabricate one; a deployment that
  keeps the shared secret is no worse off than before. The trade-off is a second key to manage
  and the non-constant-time caveat above.
* The compliance maps cannot drift, and the gap in each framework is a value in the artefact
  rather than a sentence in a comment. The ISO inventory carries a sourcing caveat that must be
  closed before an audit relies on it.
* The purple catalogue is large enough to be a real detection-validation programme, and every
  entry is a declared, safe proof payload whose tactic the pinned release supports.
* Generated artefacts (`templates/compliance/*.yaml`) must not be hand-edited: the generator's
  `--check` mode and the schema test both fail if they are.
