# ARACHNE Terraform provider — SKELETON, NOT FUNCTIONAL

> **This is a skeleton.** It is a compiles-shaped scaffold for a future, published
> `terraform-provider-arachne`; it is **not** a working provider, it is not published to any
> registry, and it is not built, tested or shipped by ARACHNE. Nothing in the ARACHNE test
> suite compiles it: Go is not part of the test environment (REQ-ECOS-003 notes the
> delivery surface, and this directory is the reserved seam for the provider half of it).

The scaffold exists so the shape of the eventual provider — its provider schema, one data
source and one resource — is decided and reviewable now, next to the Terraform *module*
(`../modules/arachne`) that is real and does deploy ARACHNE today.

## What is real here

- The Plugin Framework wiring: `main.go` serves a provider address and `provider.go`
  implements `Metadata`/`Schema`/`Configure` and registers the data source and resource.
- The Terraform schema for the `arachne_findings` data source and the `arachne_tenant`
  resource, including which attributes are computed, sensitive or required.

## What is stubbed (do not rely on it)

- **No API client.** `Configure` reads the endpoint and API key and stores them, but
  constructs no ARACHNE client; every `Read`/`Create`/`Update`/`Delete` returns a
  "skeleton" diagnostic instead of calling the API.
- **No pagination, retries, or error mapping.** The shape of those (the ARACHNE REST API
  returns `X-Next-Cursor`; the provider should retry `429`/`5xx`) is not implemented.
- **No tests, no acceptance tests, no release tooling.** The `Makefile` has the usual
  targets, but `make test` runs an empty suite.
- **No provider address is reserved.** `registry.terraform.io/arachne/arachne` is a
  placeholder; the real namespace must be claimed before publishing.

## Layout

| File | Purpose |
| ---- | ------- |
| `main.go` | Entry point; serves the provider via `providerserver`. |
| `provider.go` | Provider type, schema (`endpoint`, `api_key`), registration. |
| `data_source_findings.go` | `arachne_findings` — read findings for a scan. Stubbed `Read`. |
| `resource_tenant.go` | `arachne_tenant` — manage a project/tenant. Stubbed CRUD. |
| `go.mod` | Module definition. |
| `Makefile` | `build` / `install` / `fmt` / `vet` / `test` targets. |

## WP-16 decision: recovery deferred, and why

`REQ-ECOS-010` asks this provider to cover **projects, targets, schedules and suppression rules
with import support and acceptance tests against a fixture API**. WP-16 re-measured what the
control plane actually serves before writing Go, and the answer is that the provider cannot be
honest yet:

| Resource | create | read | delete | update |
| ---- | ------ | ---- | ------ | ------ |
| projects | `POST /projects` | `GET /projects/{slug}` | `DELETE /projects/{slug}` | **only** `PUT /projects/{slug}/retention` and `PUT /projects/{slug}/storage` |
| targets | `POST /targets` | `GET /targets/{id}` | `DELETE /targets/{id}` | **no endpoint** |
| schedules | `POST /schedules` (an upsert, so it can replace the row) | `GET /schedules` | `DELETE /schedules/{id}` | **no PATCH/PUT endpoint** |
| suppressions | `POST /suppressions` | `GET /suppressions` | `DELETE /suppressions/{id}` | **no endpoint** (a rule is revoked and re-created) |

A provider that claimed create/read/update/delete against that surface would either call an
endpoint the product does not serve — passing its own acceptance tests against a fixture server
that implements fiction — or silently map "update" onto delete-and-recreate, which is not what
Terraform users mean by it and would drop a suppression's recorded actor and reason. Neither is
acceptable, so the work is **deferred with this decision recorded** rather than half-implemented.

What would unblock it:

1. a control-plane change adding `PATCH`/`PUT` for targets, schedules and suppressions (a DET/API
   work package owns those routers, not this one);
2. then a provider built with `import` (`ResourceWithImportState`) per resource, and acceptance
   tests that drive the resource's CRUD methods against an in-process `httptest` fixture server —
   no Terraform CLI and no network, which is what makes the tests runnable here at all.

Until then the Terraform *module* (`../modules/arachne`) remains the supported deployment path;
it is real, and it deploys ARACHNE today.

## Building (for a future provider, not needed here)

```sh
cd deploy/terraform/provider
make build        # go build -o terraform-provider-arachne
make vet          # go vet ./...
```

Neither the ARACHNE CI nor its test suite runs these; a Go toolchain is not required to use
ARACHNE or its Terraform module.
