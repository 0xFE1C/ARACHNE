# ARACHNE Terraform module — provider requirements (S26, REQ-ECOS-003).
#
# The module deploys the existing ARACHNE Helm chart (S22, REQ-OPS-005), which ships in
# this repository at `deploy/helm/arachne`. It therefore needs only the Helm and
# Kubernetes providers; there is no ARACHNE-specific provider to install (the provider
# skeleton under `deploy/terraform/provider/` is not published).

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.12.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.25.0"
    }
  }
}
