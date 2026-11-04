# Vendored schemas

Data files here are consumed by shipped tools at runtime; they are never executed.

## `cyclonedx-1.5.schema.json`

* **What**: the official CycloneDX 1.5 JSON Schema (`$id`
  `http://cyclonedx.org/schema/bom-1.5.schema.json`, `$schema` JSON Schema
  draft-07).
* **Source URL**:
  <https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.5.schema.json>
  (CycloneDX specification repository).
* **Retrieved**: 2026-11-05.
* **SHA-256**:
  `2d956c1d05c092695457a91f3b5c57c749793c013ec224a0935807cfc8ae4480`.
* **Licence**: Apache License 2.0 — the schema's own `$comment` states "CycloneDX
  JSON schema is published under the terms of the Apache License 2.0". The schema
  is vendored verbatim so an installed ARACHNE can validate its SBOM offline.

Used by `arachne.tools.sbom.validate_sbom` (REQ-TRUST-011).
