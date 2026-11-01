# Reproducible builds

*Living documentation (S22, REQ-TRUST-003). Update when the build changes.*

"Reproducible" here means: **the same source tree, built twice, produces artifacts
whose only difference is the parts that cannot be deterministic** — and every one of
those parts is documented below, with the way to pin it. An auditor should be able to
take a released image's digest and re-derive it from the tagged source.

## What is deterministic already

| Artifact | Determinism | Mechanism |
|---|---|---|
| The SBOM (`python -m arachne.tools.sbom`) | **Byte-identical** for the same environment and timestamp | Sorted keys, sorted components, `serialNumber` derived from the component set (RFC 4122 name-based UUID), the clock taken from `SOURCE_DATE_EPOCH` or `--timestamp`, never `now()` first |
| The compliance maps, check catalogue, report schemas | Byte-identical (they are data files) | Versioned YAML/JSON in `src/arachne/templates/`, pinned by schema tests |
| The Python package | Deterministic content for the same wheel inputs | `hatchling`; no build-time code generation |

The SBOM's honesty rule: components come from the **installed** distributions
reachable from ARACHNE's declared dependencies (`importlib.metadata`), transitively,
with environment markers evaluated for the running interpreter. A dependency that is
missing with no marker is a hard error — a partial environment must not produce a
partial (and unlabelled) SBOM.

## Pinning the clock

Every timestamped artifact takes its clock, in order, from:

1. an explicit `--timestamp` argument;
2. `SOURCE_DATE_EPOCH` (the [reproducible-builds.org](https://reproducible-builds.org/docs/source-date-epoch/) convention);
3. the current time.

The release workflow sets `SOURCE_DATE_EPOCH` from the tag's commit timestamp, so
re-running a release for the same tag yields the same SBOM.

## Pinning the toolchain

* **Python**: the Dockerfile builds `FROM python:3.12-slim` (digest-pinnable with
  `@sha256:` at build time; see below).
* **cosign**: pinned in `.github/workflows/release.yml` via the `COSIGN_VERSION` env
  (`v2.4.1` at the time of writing) through `sigstore/cosign-installer@v3`.
* **GitHub Actions**: every `uses:` is pinned to a major version tag. For a stronger
  guarantee (supply-chain auditing of the actions themselves), pin them to full
  commit SHAs — the major tags were chosen for maintainability; SHAs are the
  stricter option and a one-line change per action.
* **pip-audit**: bounded `>=2.7,<3` in the `audit` extra; the release job installs
  and runs it with no `continue-on-error` (REQ-TRUST-003).

To pin the base image by digest, replace the tag in `docker/Dockerfile`:

```dockerfile
FROM python@sha256:<digest> AS base
```

with the digest of `python:3.12-slim` for your architecture. That is a deliberate
trade (a digest pin freezes security patches of the base image behind a review), so
it is an operator/deployment decision, not the shipped default.

## Reproducing an image build

```sh
git checkout v<version>
docker build -f docker/Dockerfile -t arachne:v<version> code
docker image inspect --format '{{index .RepoDigests 0}}' arachne:v<version>
```

Two builds of the same commit on the same builder produce the same layers. Across
different machines the layers can differ (build hosts, resolvers, timestamps in the
filesystem) — which is exactly why the release pipeline publishes and **signs the
pushed digest**, and why the verification contract is:

```sh
cosign verify <image>@<digest> \
  --certificate-identity-regexp '^https://github.com/<owner>/<repo>/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The signature's identity is the GitHub OIDC claim of the release workflow (keyless —
no long-lived key exists to rotate or leak), and the SLSA-style provenance
(`actions/attest-build-provenance`) binds the digest to the source commit and build
instructions.

## Known non-determinism (and why it is acceptable)

* **Docker layer timestamps** — the image's filesystem carries build-time mtimes.
  The digest signing makes the *published* artifact immutable regardless.
* **`pip` resolution at build time** — the Dockerfile installs `.[postgres]` without a
  lock file, so a fresh build picks current compatible versions (the declared ranges
  are upper-bounded where it matters). A deployment that needs bit-identical
  environments should `pip freeze` into its own base layer; the SBOM tells you
  exactly what a given image actually contains, which is the property an audit needs
  even when two builds differ.
* **The report's `generated_at`** — a scan report stamps when it was built (from the
  scan record, not the wall clock of the renderer); rendering the same DTO is
  byte-identical (ADR-06, pinned by the report-QA suite).

## Verification commands

```sh
python -m arachne.tools.sbom --output sbom.cdx.json   # the SBOM
python -m arachne.tools.credentials_gate              # no default credentials
python -m pytest tests/unit/test_sbom.py              # the SBOM contract
python -m pytest tests/unit/test_release_workflow.py  # the release chain's shape
```
