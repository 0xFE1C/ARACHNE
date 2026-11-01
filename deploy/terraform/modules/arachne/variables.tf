# Inputs for the ARACHNE module (S26, REQ-ECOS-003).
#
# The variables map onto the Helm chart's values one-for-one where it matters; anything not
# exposed here is set through `extra_values`. Secrets have no default and are nullable, so a
# plan is not forced to carry a credential it has no intention of managing.

variable "namespace" {
  description = "Kubernetes namespace ARACHNE is deployed into."
  type        = string
  default     = "arachne"
}

variable "release_name" {
  description = "Helm release name (the resource prefix for every object the chart renders)."
  type        = string
  default     = "arachne"
}

variable "create_namespace" {
  description = "Create the namespace if it does not exist (set false for a pre-existing one)."
  type        = bool
  default     = true
}

variable "chart_path" {
  description = "Path to the ARACHNE Helm chart. Defaults to the chart shipped in this repository."
  type        = string
  default     = null
}

variable "chart_version" {
  description = "Chart version to install; null installs whatever the chart directory declares."
  type        = string
  default     = null
}

variable "image_repository" {
  description = "Container image repository for the API and agent pods."
  type        = string
  default     = "ghcr.io/arachne/arachne"
}

variable "image_tag" {
  description = "Container image tag; empty uses the chart's appVersion."
  type        = string
  default     = ""
}

variable "api_replicas" {
  description = "API replica count (the API is stateless and lays out across nodes)."
  type        = number
  default     = 2
}

variable "agent_replicas" {
  description = "Agent-pool replica count (0 disables the distributed pool)."
  type        = number
  default     = 2
}

variable "postgres_enabled" {
  description = "Deploy the in-chart Postgres. Set false to point at a managed database instead."
  type        = bool
  default     = true
}

variable "evidence_backend" {
  description = "Evidence storage backend: local (shared RWX volume) or s3."
  type        = string
  default     = "local"

  validation {
    condition     = contains(["local", "s3"], var.evidence_backend)
    error_message = "evidence_backend must be \"local\" or \"s3\"."
  }
}

variable "autoscaling_enabled" {
  description = "Enable the plain HorizontalPodAutoscaler for the agent pool."
  type        = bool
  default     = false
}

variable "autoscaling_keda_enabled" {
  description = "Enable the KEDA ScaledObject (supersedes the HPA; scale-to-zero capable)."
  type        = bool
  default     = false
}

variable "api_keys" {
  description = "API keys as \"label:role:secret[;...]\" (sensitive). Null leaves the chart's own Secret in charge."
  type        = string
  default     = null
  sensitive   = true
}

variable "agent_api_key" {
  description = "Scanner-role key the agent pool authenticates with (sensitive)."
  type        = string
  default     = null
  sensitive   = true
}

variable "postgres_password" {
  description = "Password for the in-chart Postgres (sensitive). Null requires a pre-created Secret."
  type        = string
  default     = null
  sensitive   = true
}

variable "extra_values" {
  description = "Additional chart values, deep-merged after the module's own (a YAML/JSON list)."
  type        = list(string)
  default     = []
}

variable "timeout" {
  description = "Seconds to wait for the release to become ready."
  type        = number
  default     = 600
}

variable "atomic" {
  description = "Roll back the release when an install or upgrade fails."
  type        = bool
  default     = true
}

variable "wait" {
  description = "Wait for the release's resources to be ready before returning."
  type        = bool
  default     = true
}
