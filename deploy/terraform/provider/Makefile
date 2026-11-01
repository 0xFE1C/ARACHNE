# SKELETON Makefile for the ARACHNE Terraform provider (REQ-ECOS-003).
#
# These targets are the shape a published provider would grow into; nothing here runs in
# ARACHNE's CI and a Go toolchain is not required to use ARACHNE (see README.md).

BINARY := terraform-provider-arachne
VERSION ?= dev

.PHONY: build install fmt vet test clean

build: ## Build the provider binary
	go build -ldflags "-X main.version=$(VERSION)" -o $(BINARY)

install: build ## Install into the local plugin cache for manual testing
	mkdir -p "$$HOME/.terraform.d/plugins"
	cp $(BINARY) "$$HOME/.terraform.d/plugins/$(BINARY)"

fmt: ## Format the Go sources
	gofmt -s -w .

vet: ## Run go vet
	go vet ./...

test: ## Run the (currently empty) unit tests
	go test ./... -count=1

clean: ## Remove build output
	rm -f $(BINARY)
