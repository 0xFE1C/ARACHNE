# ARACHNE Terraform module — the deployment itself (S26, REQ-ECOS-003).
#
# The module is a thin, honest wrapper over the Helm chart this repository already ships
# (`deploy/helm/arachne`, S22/REQ-OPS-005): it creates the namespace and installs the
# chart, mapping a small, typed surface of inputs onto the chart's values and keeping the
# secrets out of the plan with `set_sensitive`. It invents no Kubernetes objects of its own,
# so what Terraform deploys is exactly what `helm install` deploys.

locals {
  # The chart's fullname helper: the release name wins when it already contains the chart
  # name, else the chart name is appended. Mirrored here so the output service names match
  # the objects Helm actually creates (the chart applies no nameOverride/fullnameOverride).
  chart_name = "arachne"
  fullname = (
    var.release_name != "" && strcontains(var.release_name, local.chart_name)
    ? var.release_name
    : "${var.release_name}-${local.chart_name}"
  )

  # Path to the chart shipped in this repository when the caller names none.
  chart_path = coalesce(var.chart_path, "${path.module}/../../../helm/arachne")

  # The image tag is omitted entirely when empty so the chart's own appVersion default
  # applies; emitting `tag: null` into the values would override it with a literal null.
  image_values = merge(
    { repository = var.image_repository },
    var.image_tag != "" ? { tag = var.image_tag } : {},
  )
}

resource "kubernetes_namespace_v1" "arachne" {
  count = var.create_namespace ? 1 : 0

  metadata {
    name = var.namespace
    labels = {
      "app.kubernetes.io/name"       = local.chart_name
      "app.kubernetes.io/part-of"    = local.chart_name
      "app.kubernetes.io/managed-by" = "terraform"
    }
  }
}

resource "helm_release" "arachne" {
  name      = var.release_name
  namespace = var.namespace
  chart     = local.chart_path
  version   = var.chart_version

  timeout = var.timeout
  atomic  = var.atomic
  wait    = var.wait

  # Non-secret values: the module's block first, then the caller's `extra_values` so an
  # operator can override anything the module does not expose.
  values = concat(
    [
      yamlencode({
        image   = local.image_values
        api     = { replicas = var.api_replicas }
        agent   = { replicas = var.agent_replicas }
        postgres = { enabled = var.postgres_enabled }
        evidence = { backend = var.evidence_backend }
        autoscaling = {
          enabled = var.autoscaling_enabled
          keda    = { enabled = var.autoscaling_keda_enabled }
        }
      })
    ],
    var.extra_values,
  )

  # Secrets ride in `set_sensitive`, which the Helm provider marks sensitive: they never
  # appear in a plan or a state diff. Each is applied only when the caller provided it, so
  # a deployment managing a Secret out-of-band keeps the chart's `existingSecret` path.
  dynamic "set_sensitive" {
    for_each = var.api_keys == null ? [] : [var.api_keys]
    content {
      name  = "api.auth.apiKeys"
      value = set_sensitive.value
    }
  }

  dynamic "set_sensitive" {
    for_each = var.agent_api_key == null ? [] : [var.agent_api_key]
    content {
      name  = "agent.auth.apiKey"
      value = set_sensitive.value
    }
  }

  dynamic "set_sensitive" {
    for_each = var.postgres_password == null ? [] : [var.postgres_password]
    content {
      name  = "postgres.auth.password"
      value = set_sensitive.value
    }
  }

  depends_on = [kubernetes_namespace_v1.arachne]
}
