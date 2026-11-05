# CI integration (REQ-ECOS-003)

> **Owner:** Ecosystem group · **Last verified:** 2026-11-05 · **Review interval:** 180 days

ARACHNE's delivery surface: run the offline IaC/CI gate in a pipeline and put its findings
where a reviewer reads them — GitHub pull-request annotations, a GitLab Code Quality report,
or SARIF in Code Scanning. Everything here is offline by construction; nothing dials out
unless you point it at a control plane.

## What ships

| Artefact | Path | What it is |
| -------- | ---- | ---------- |
| GitHub Action | `src/arachne/templates/ci/github/action.yml` | Composite action: gate + annotations + optional SARIF upload. |
| GitLab component | `src/arachne/templates/ci/gitlab/component.yml` | Reusable job: gate + `codequality` artifact. |
| CLI entry | `src/arachne/tools/ci_annotate.py` | `python -m arachne.tools.ci_annotate` — the one command both call. |
| Examples | `examples/ci/github-workflow.yml`, `examples/ci/gitlab-ci.yml` | Copy-paste workflows. |
| Terraform module | `deploy/terraform/modules/arachne/` | Deploys ARACHNE via the shipped Helm chart. |
| Terraform provider | `deploy/terraform/provider/` | **Skeleton only** — not functional, not published. |

## The gate

The gate is the existing pre-deploy review (S23, REQ-POSTURE-002):

```sh
arachne iac gate PATH --fail-on high
```

It scans a local tree (Terraform, Kubernetes manifests, CI workflow files) with the real
M5 checks and exits per the F-07-05 policy:

| Exit | Meaning |
| ---- | ------- |
| `0` | clean — nothing at or above the threshold |
| `1` | findings exist, all below the threshold |
| `2` | at least one finding at or above the threshold |

`--fail-on` accepts `info|low|medium|high|critical|none` (`none` disables the gate and always
exits 0). The scan is offline: the target is a `repo:` reference, no clone or fetch happens,
and the self-attestation says so.

A scan writes to the control-plane database, so a CI job needs the schema first:

```sh
export ARACHNE_DATABASE_URL="sqlite:///$PWD/.arachne-ci.db"
arachne db upgrade        # idempotent
```

A job-local SQLite database is enough; point `ARACHNE_DATABASE_URL` at Postgres to keep a
history.

## The tool: `python -m arachne.tools.ci_annotate`

```sh
# Review a tree and print GitHub workflow commands to stdout:
python -m arachne.tools.ci_annotate --path . --format github --fail-on high

# Annotate a stored report (no database):
python -m arachne.tools.ci_annotate --report report.json --format sarif -o report.sarif

# Everything at once:
python -m arachne.tools.ci_annotate --path . --format all --output-dir .arachne-ci
```

| Flag | Meaning |
| ---- | ------- |
| `--path PATH` / `--report FILE` | Review a tree (runs the gate), or read a stored report. |
| `--fail-on LEVEL` | Gate threshold (default `high`). |
| `--format` | `github` (annotations, default), `gitlab` (Code Quality), `sarif`, `json`, `all`. |
| `--output FILE` | Write the single artefact to a file instead of stdout. |
| `--output-dir DIR` | Where `--format all` writes (default `.arachne-ci`). |
| `--max-annotations N` | Cap on GitHub annotations, worst-first (default 50). |

The process exit code is the gate's (0/1/2). Annotations go to **stdout** (GitHub parses
workflow commands from there); the human summary goes to stderr.

## GitHub Actions

Copy `action.yml` to `.github/actions/arachne-gate/action.yml` (or `uses:` its path) and add
a job — see `examples/ci/github-workflow.yml`:

```yaml
permissions:
  contents: read
  security-events: write   # only for the SARIF upload
  pull-requests: write     # only for annotations on forked PRs

jobs:
  arachne:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: {python-version: "3.12"}
      - run: pip install arachne
      - uses: ./.github/actions/arachne-gate
        with:
          path: .
          fail-on: high
          format: sarif          # or `github` for plain annotations
          upload-sarif: "true"
```

Inputs: `path`, `fail-on`, `format`, `api-url`, `api-key`, `sarif-file`, `upload-sarif`,
`python`. Outputs: `exit-code`, `sarif-file`.

* **Offline.** The action reviews the checked-out tree; only the optional `api-url` step
  dials out.
* **Exit code.** The gate step always succeeds so the SARIF upload can run; a final step
  re-raises the gate's exit code, so a finding at or above the threshold red-Xes the job.
* **SARIF.** `format: sarif` writes the file and uploads it with
  `github/codeql-action/upload-sarif` **only when the file exists** (guarded by a step
  output). Requires `security-events: write`.
* **Annotations.** `format: github` prints `::error`/`::warning`/`::notice` lines to stdout;
  GitHub renders them on the diff. Only findings at or above `fail-on` are annotated, worst
  first, capped at `--max-annotations`.

## GitLab CI

Publish the component in a project under `templates/arachne-gate/`, then — see
`examples/ci/gitlab-ci.yml`:

```yaml
include:
  - component: gitlab.com/your-org/arachne/arachne-gate@0.1.0
    inputs:
      path: "."
      fail_on: high
```

Inputs: `path`, `fail_on`, `stage`, `image`, `install`, `allow_failure`. The job runs
`python -m arachne.tools.ci_annotate --format gitlab`, writes `codequality.json`, and
publishes it as the `codequality` report (`when: always`, so a failed review still shows its
findings). Rules default to merge requests and the default branch; `allow_failure` defaults
to `false` so the gate blocks the merge.

## Terraform

The module deploys the Helm chart this repository ships (`deploy/helm/arachne`):

```hcl
module "arachne" {
  source = "github.com/0xFE1C/ARACHNE//deploy/terraform/modules/arachne"

  namespace    = "security"
  release_name = "arachne"
  api_keys          = var.arachne_api_keys          # sensitive
  agent_api_key     = var.arachne_agent_api_key     # sensitive
  postgres_password = var.arachne_postgres_password # sensitive
}
```

See `deploy/terraform/modules/arachne/README.md` for every input and output. It creates the
namespace and installs the chart; secrets ride in `set_sensitive` so they never enter the
plan.

**Validation status.** The module is written to be `terraform validate`-able, but the
`terraform` binary is **not** part of the ARACHNE test environment and no `terraform
validate` was run for this change. The test suite pins the module structurally instead
(`tests/test_ci_surfaces.py`): every variable is referenced, every output is defined, and the
chart path/provider requirements are asserted. Run `terraform fmt -check` and `terraform
validate` locally before changing the module.

## Terraform provider — a skeleton

`deploy/terraform/provider/` is an explicit **skeleton**: `main.go`, `provider.go`,
`data_source_findings.go`, `resource_tenant.go`, `go.mod` and a `Makefile`, shaped for the
Terraform Plugin Framework. It is **not functional and not published**: there is no API
client, every CRUD/Read returns a "skeleton" diagnostic, and Go is not part of the test
suite. Do not use it to manage anything. It exists to fix the eventual provider's shape next
to the real module.

## See also

- The CI gate policy (F-07-05) — enforced through the exit-code contract above.
- `deploy/terraform/modules/arachne/README.md` — module inputs/outputs.
- `tests/test_ci_surfaces.py` — the acceptance test (`action run on the misconfigured fixture
  produces annotations naming the planted violation, exit 2`).
