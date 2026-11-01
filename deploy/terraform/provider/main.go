// Command terraform-provider-arachne is the SKELETON entry point for an ARACHNE Terraform
// provider (REQ-ECOS-003).
//
// It is not a published provider and not part of ARACHNE's test suite (Go is not in the test
// environment). It exists to fix the shape of the eventual provider next to the real
// Terraform module under ../modules/arachne. See README.md.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
)

// version is stamped at build time (-ldflags "-X main.version=...").
var version = "dev"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "run the provider with debugger support")
	flag.Parse()

	opts := providerserver.ServeOpts{
		// SKELETON: placeholder address; the real namespace must be claimed before release.
		Address: "registry.terraform.io/arachne/arachne",
		Debug:   debug,
	}

	if err := providerserver.Serve(context.Background(), New(version), opts); err != nil {
		log.Fatal(err.Error())
	}
}
