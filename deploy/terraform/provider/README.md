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

## Building (for a future provider, not needed here)

```sh
cd deploy/terraform/provider
make build        # go build -o terraform-provider-arachne
make vet          # go vet ./...
```

Neither the ARACHNE CI nor its test suite runs these; a Go toolchain is not required to use
ARACHNE or its Terraform module.
