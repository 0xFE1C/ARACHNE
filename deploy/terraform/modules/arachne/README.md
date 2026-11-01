# ARACHNE Terraform module

Installs ARACHNE on Kubernetes by deploying the Helm chart shipped in this repository
(`code/deploy/helm/arachne`, S22 / REQ-OPS-005). The module is a typed wrapper over that
chart: it creates the namespace and installs the release, maps a small surface of inputs
onto the chart's values, and keeps credentials out of the plan with the Helm provider's
`set_sensitive`. What Terraform applies is exactly what `helm install` applies — the module
adds no Kubernetes objects of its own.

Delivery-surface requirement: REQ-ECOS-003 (S26).

## Usage

```hcl
module "arachne" {
  source = "github.com/arachne-project/arachne//code/deploy/terraform/modules/arachne"

  namespace    = "security"
  release_name = "arachne"
  image_tag    = "0.1.0"

  api_replicas   = 3
  agent_replicas = 4

  # Secrets have no default. Provide them here (from your secret manager) or leave them
  # null and manage a Kubernetes Secret yourself via the chart's `existingSecret` values
  # through `extra_values`.
  api_keys          = var.arachne_api_keys
  agent_api_key     = var.arachne_agent_api_key
  postgres_password = var.arachne_postgres_password
}
```

Because `chart_path` defaults to `${path.module}/../../../helm/arachne`, a local checkout
works with no arguments; a published module should pin `chart_path` (or vendor the chart).
`chart_version` is `null` by default, which installs whatever the chart directory declares.

## Requirements

| Name | Version |
| ---- | ------- |
| terraform | >= 1.5.0 |
| helm | >= 2.12.0 |
| kubernetes | >= 2.25.0 |

## Inputs

| Name | Description | Default |
| ---- | ----------- | ------- |
| `namespace` | Namespace to deploy into | `"arachne"` |
| `release_name` | Helm release name | `"arachne"` |
| `create_namespace` | Create the namespace if absent | `true` |
| `chart_path` | Path to the chart | the chart in this repository |
| `chart_version` | Chart version to install | `null` (chart's own) |
| `image_repository` | Image repository | `"ghcr.io/arachne/arachne"` |
| `image_tag` | Image tag | `""` (chart appVersion) |
| `api_replicas` | API replica count | `2` |
| `agent_replicas` | Agent-pool replica count | `2` |
| `postgres_enabled` | Deploy the in-chart Postgres | `true` |
| `evidence_backend` | `local` or `s3` | `"local"` |
| `autoscaling_enabled` | Plain HPA for the agent pool | `false` |
| `autoscaling_keda_enabled` | KEDA ScaledObject (scale-to-zero) | `false` |
| `api_keys` | `label:role:secret[;...]` (sensitive) | `null` |
| `agent_api_key` | Agent pool key (sensitive) | `null` |
| `postgres_password` | Postgres password (sensitive) | `null` |
| `extra_values` | Extra chart values, applied last | `[]` |
| `timeout` | Seconds to wait for readiness | `600` |
| `atomic` | Roll back a failed install/upgrade | `true` |
| `wait` | Wait for resources to be ready | `true` |

## Outputs

| Name | Description |
| ---- | ----------- |
| `release_name` | Helm release name |
| `namespace` | Deployment namespace |
| `status` | Release status |
| `revision` | Release revision |
| `api_service_name` | API Service name (`<fullname>-api`) |
| `postgres_service_name` | Postgres Service name (`<fullname>-postgres`) |

## Validation

The module is written to be `terraform init && terraform validate`-able against the Helm and
Kubernetes providers (this has not been run here — the `terraform` binary is **not** part of
the ARACHNE test environment, and no `terraform validate` was executed). The test suite pins
the module's structure instead (`code/tests/test_ci_surfaces.py`): every declared variable is
referenced and every output is defined. Run `terraform fmt -check` and `terraform validate`
locally before changing it.
