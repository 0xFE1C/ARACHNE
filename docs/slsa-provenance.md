# SLSA v1.2 Build L3 provenance

*Living documentation (S22, REQ-TRUST-011). Update when the release chain changes.*

This page states precisely what ARACHNE's release provenance claims, which platform
provides it, how a third party verifies it, and what remains outside our control. It
does **not** claim that the release artefact is reproducible across machines (that is
[reproducible-builds.md](reproducible-builds.md)) or that the image is free of
vulnerabilities (that is the dependency audit).

## What "SLSA v1.2 Build L3" means here

SLSA's Build track levels describe **how much a consumer can trust the provenance of a
build**, not the security of the built software. Build L3 has two load-bearing
requirements:

1. **A hardened, isolated build platform.** The build runs on managed infrastructure
   that user-controlled build steps cannot tamper with, and build credentials are not
   exposed to the build.
2. **Non-forgeable provenance.** The platform itself generates and signs the
   provenance, so the person who triggered the build cannot fabricate or edit it.

ARACHNE's release artefacts are the **container image** published to GHCR by the
`image` job in `.github/workflows/release.yml`. That job runs on a GitHub-hosted
runner (the hardened platform) and uses
[`actions/attest-build-provenance@v1`](https://github.com/actions/attest-build-provenance)
to emit a signed SLSA v1.2 provenance attestation bound to the image digest. The
attestation's signature is a short-lived Sigstore certificate whose OIDC identity is
this repository's release workflow. That is the L3 evidence.

The SBOM is a separate, signed attestation: `cosign attest --type cyclonedx` binds
`sbom.cdx.json` to the same image digest, keyless, under the same workflow identity.

## Which platform provides it

| Property | Provider |
|---|---|
| Hardened, isolated build | GitHub-hosted `ubuntu-latest` runner |
| Provenance generation | `actions/attest-build-provenance@v1` (GitHub's builder) |
| Signing identity | GitHub Actions OIDC (`https://token.actions.githubusercontent.com`) |
| Signing material | Sigstore Fulcio (short-lived certificate) |
| Transparency log | Sigstore Rekor |
| Attestation storage | GitHub attestations API and, with `push-to-registry`, the GHCR registry |

## What the shipped tools do (and do not do)

`python -m arachne.tools.provenance` writes the same SLSA v1.2 statement shape offline:
an in-toto `Statement/v1` envelope with predicate
`https://slsa.dev/provenance/v1`, the wheel/sdist and SBOM as sha256 subjects, a
`buildDefinition`, and `runDetails` (builder id, invocation id, start/finish times,
and the SBOM as a byproduct). It is a pure function of the named files and an explicit
timestamp, and `--verify` re-derives every subject digest and exits non-zero on a
mismatch.

That local document **does not satisfy L3**: it is written by the same user, on the
same machine, that produced the artefacts, with no isolation, and it is unsigned. The
tool therefore defaults to the honest builder id
`https://arachne.dev/builders/local/v1`; only the CI job passes GitHub's builder id,
because only CI can prove it. Treat the local tool as a way to describe and check an
artefact set, not as an alternative to the CI attestation.

`python -m arachne.tools.sbom` validates its output against the vendored official
CycloneDX 1.5 JSON Schema (`src/arachne/data/schemas/cyclonedx-1.5.schema.json`,
Apache-2.0; see the note beside it) by default when writing a file. `--check PATH`
validates an existing document. Validation requires the `jsonschema` package
(`pip install -e '.[dev]'`); when it is absent the tool fails with the install command
rather than silently passing.

## Third-party verification

Set these to the release you are checking:

```sh
REPO=owner/arachne
IMAGE=ghcr.io/$REPO
DIGEST=sha256:<published digest>
TAG=v<version>
```

### 1. Verify the SLSA provenance attestation

With the GitHub CLI (the published verifier for GitHub attestations):

```sh
gh attestation verify "oci://${IMAGE}:${TAG}" --repo "$REPO"
```

Or with cosign v2.4.1, pinning the expected workflow identity:

```sh
cosign verify-attestation --type slsaprovenance1 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp "^https://github.com/${REPO}/" \
  "${IMAGE}@${DIGEST}"
```

A non-zero exit means the provenance is missing, unsigned, or was not produced by this
repository's workflow. Anything less than the pinned issuer **and** identity check
proves only that *some* Sigstore identity signed *something*.

### 2. Verify the image signature

```sh
cosign verify "${IMAGE}@${DIGEST}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp "^https://github.com/${REPO}/"
```

### 3. Extract and validate the SBOM

```sh
cosign verify-attestation --type cyclonedx \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp "^https://github.com/${REPO}/" \
  "${IMAGE}@${DIGEST}" \
  | jq -r '.payload' | base64 -d | jq -r '.predicate' > sbom.cdx.json

python -m arachne.tools.sbom --check sbom.cdx.json
```

`--check` validates against the vendored CycloneDX 1.5 schema. A schema-valid document
is not by itself evidence that the attestation is authentic — step 2's signature and
step 1's identity check are what bind this SBOM to the image.

### 4. Verify an offline provenance document (optional)

If you have a provenance file produced by the shipped tool and the original artefacts:

```sh
python -m arachne.tools.provenance --verify provenance.intoto.jsonl \
  --artifact dist/arachne-<version>-py3-none-any.whl \
  --artifact dist/arachne-<version>.tar.gz \
  --sbom sbom.cdx.json
```

This proves only that the file's digests match the files you have. It does **not**
prove who produced the file; the signature in step 1 does that.

## Release workflow shape

The release workflow is the evidence chain, and `tests/unit/test_release_workflow.py`
pins it:

```
audit (pip-audit --strict, release-blocking)
  -> sbom (shipped generator -> schema validation -> upload)
  -> image (build -> cosign sign -> cosign attest cyclonedx -> cosign verify
            -> actions/attest-build-provenance -> cosign verify-attestation)
```

The image job's attestation is the provenance artefact for this release line. The
workflow does not currently publish the wheel/sdist as release assets, so there is no
separate GitHub attestation for them; if they are published later, add
`actions/attest-build-provenance` with `subject-path` on those files in a build job and
verify them with `gh attestation verify <file> --repo "$REPO"`.

## Residual gaps (stated plainly)

* **Keyless trust root.** Verification trusts the Sigstore Fulcio CA, the Rekor
  transparency log, and the TUF root metadata that cosign fetches. If that trust root
  is compromised or mis-issued, a signature can verify for an identity it should not
  hold. This is a property of keyless Sigstore, not of ARACHNE.
* **Public vs private Sigstore.** Public repositories use the public-good Sigstore
  instance; private/internal repositories use GitHub's private Sigstore. The verifier
  must use the trust root appropriate to the repository's visibility.
* **The attestation covers the image digest, not image contents.** It binds *what was
  built* to *how it was built*; it does not assert that the content is safe. The SBOM
  and the dependency audit are the content evidence.
* **Cross-machine reproducibility is not claimed.** Provenance and reproducibility are
  different guarantees; see [reproducible-builds.md](reproducible-builds.md).
* **Unsigned local provenance.** The shipped `arachne.tools.provenance` document is
  unsigned and user-authored by construction; it must not be presented as L3 evidence.