# ADR-350 · Native image scanning, hostile archives in a temporary root, and a declared cloud-provider ledger

> **Owner:** ARACHNE architecture group · **Last verified:** 2026-11-05 · **Review interval:** 1825 days

| Field | Value |
|---|---|
| Status | accepted |
| Date | 2026-11-03 |
| Deciders | ARACHNE detection engineering, safety owner |
| Extends | ADR-250.4 (the byte-exact read path) with a second documented call site; ADR-05 (one egress path) |
| Requirements | REQ-DET-016, REQ-DET-017 |

## Context

Two gaps share one cause: a claim that was documented but not implemented, and a capability that
was implemented but not declared.

1. **Container images.** `m5.registry-scan` lists a registry catalog, and the module documentation
   said an external Trivy/Syft-class scanner ran "when `ARACHNE_M5_SBOM_TOOL` is configured and
   `ARACHNE_M5_REGISTRY_SCAN` is enabled". No code ever invoked a tool, and both switches were
   off, so the air-gapped deployment REQ-DET-016 is written for could not read a single package
   out of an image.
2. **Cloud providers past the big three.** M5 covers AWS, Azure and GCP. A customer on OCI,
   Alibaba Cloud or DigitalOcean received neither posture coverage nor a statement that the
   product does not cover them. ADR-345 already decided that a declared gap beats a token check;
   this work has to make that declaration exist.

The first item is the highest-risk parsing work in the programme: an image layer is an
attacker-controlled archive, and the layer content arrives from a host that may itself be
compromised. A parser that follows a symlink or trusts a declared size writes to the scanner's
filesystem.

## Decision

**1. Image scanning is native and on by default, with no external process.**
`m5.image-scan` resolves `GET /v2/<repo>/manifests/<ref>` (one index level, never two), fetches
each `GET /v2/<repo>/blobs/<digest>` through the shared scoped client, verifies the blob's
`sha256` digest before reading it, and matches the unpacked packages against the offline index.
`ARACHNE_M5_IMAGE_SCAN=false` is the only way to turn it off. The layer bytes are the second
documented caller of `ScopedHttpClient.request_bytes` (ADR-250.4): a compressed, digest-bearing
container run through the text decoder and the redactor would be corrupted and its digest would
no longer verify. Scope validation, rate limiting and audit are unchanged.

**2. The layer is treated as hostile and unpacked only into a temporary root.**
A header-only validation pass runs before any byte is written: only regular files and
directories are accepted (a symlink, hardlink, device or FIFO refuses the whole layer), absolute
paths and `..` components refuse it, and the declared cumulative size, per-file size and member
count are capped. Extraction is all-or-nothing into `tempfile.mkdtemp`, never the workspace,
with `O_NOFOLLOW`, without modes, owners, timestamps or extended attributes, and the temporary
root is removed in a `finally`. The image and its contents are never executed. A distroless
image has no package database and is a valid empty result.

**3. The external scanner path remains, as a report import rather than a process.**
When `ARACHNE_M5_REGISTRY_SCAN=true`, `ARACHNE_M5_SBOM_TOOL` names a known shape and
`ARACHNE_M5_SBOM_REPORT` names a file, that JSON report is read (bounded) and merged into the
native findings. The tool is never launched: a launcher that pulled the image itself would make
its own network requests outside the scoped client — no scope check, no rate limit, no audit
line — which is exactly the property REQ-DET-016 forbids. Importing the report is also the only
variant that works air-gapped, which is the requirement's whole premise.

**4. Cloud breadth is a ledger, not a token check.**
`arachne.modules.cloud_providers` is one row per named provider: `supported` with the registered
checks that cover it (and, for a newly added check, the exact read-only `(GET, path)` operations
it may use), or `not_supported` with the reason. The coverage ledger renders it. DigitalOcean is
covered by `m5.do-posture`: four documented GETs, a `cloud-token` credential from the vault whose
bearer token the broker injects into one request and never hands the check, and four posture
conditions over the account's own fields. OCI and Alibaba Cloud are `not_supported` with their
signing schemes named as the reason: a partial RSA-SHA256 or HMAC-SHA1 implementation would
misreport posture, and a green tick backed by a guess is worse than the stated gap.

## Consequences

- Positive: an air-gapped deployment can read an image's packages and advisories with nothing
  installed, and every byte it read passed the scope gate and the audit trail.
- Positive: the cloud story is now a number with a qualifier — four providers supported, two
  declared gaps with reasons — instead of a partial silence.
- Negative: the shipped advisory index is small (a handful of Debian/Alpine/language entries), so
  the native scan is only as good as the operator's corpus (`ARACHNE_M5_PROBES` replaces it).
- Negative: a zstd-compressed layer is refused rather than scanned, because the standard library
  cannot read it and this path sponsors no external process. The refusal is reported, so a silent
  gap cannot occur.
- Negative: OCI and Alibaba customers read `not_supported`. That is the correct outcome per
  ADR-345.

## Alternatives rejected

- **Launch Trivy/Syft and parse its output.** It would need the image pulled, which the tool would
  do itself, outside the scope gate; and it would not work air-gapped.
- **Unpack with `tarfile.extractall` and a filter.** The extraction is small enough to write
  explicitly, and an explicit loop is what makes "all-or-nothing" and "no metadata applied"
  reviewable.
- **A generic alpha "cloud posture" check with a token.** REQ-DET-017 forbids exactly this: a
  check that cannot read the provider's fields would report clean accounts it never saw.
