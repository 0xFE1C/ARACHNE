# Outputs for the ARACHNE module (S26, REQ-ECOS-003).

output "release_name" {
  description = "The Helm release name."
  value       = helm_release.arachne.name
}

output "namespace" {
  description = "The namespace ARACHNE was deployed into."
  value       = helm_release.arachne.namespace
}

output "status" {
  description = "The release status (deployed, failed, ...)."
  value       = helm_release.arachne.status
}

output "revision" {
  description = "The release revision number."
  value       = helm_release.arachne.metadata[0].revision
}

output "api_service_name" {
  description = "The in-cluster Service the API serves on (chart fullname + -api)."
  value       = "${local.fullname}-api"
}

output "postgres_service_name" {
  description = "The in-cluster Service Postgres serves on (chart fullname + -postgres)."
  value       = "${local.fullname}-postgres"
}
