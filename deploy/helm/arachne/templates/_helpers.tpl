{{/* ARACHNE chart helpers (S22). */}}

{{- define "arachne.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "arachne.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "arachne.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "arachne.labels" -}}
helm.sh/chart: {{ include "arachne.chart" . }}
{{ include "arachne.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "arachne.selectorLabels" -}}
app.kubernetes.io/name: {{ include "arachne.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "arachne.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "arachne.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "arachne.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}

{{- /* The Postgres connection URL: the chart's Postgres when enabled, else the
override. The password is always secretKeyRef — never an inline value. */ -}}
{{- define "arachne.databaseUrl" -}}
{{- if .Values.postgres.enabled -}}
postgresql+psycopg://{{ .Values.postgres.auth.username }}:$(POSTGRES_PASSWORD)@{{ include "arachne.fullname" . }}-postgres:5432/{{ .Values.postgres.auth.database }}
{{- else -}}
{{- required "postgres.enabled=false requires databaseUrl" .Values.databaseUrl -}}
{{- end -}}
{{- end -}}

{{- /* Fail the render (REQ-OPS-006) unless every required secret source exists. */ -}}
{{- define "arachne.requireSecrets" -}}
{{- if and .Values.postgres.enabled (not (or .Values.postgres.auth.existingSecret .Values.postgres.auth.password)) -}}
{{- fail "postgres.auth.password (or postgres.auth.existingSecret) is required — this chart ships no default credentials (REQ-OPS-006)" -}}
{{- end -}}
{{- if and (not (or .Values.api.auth.existingSecret .Values.api.auth.apiKeys)) (not .Values.vault.enabled) -}}
{{- fail "api.auth.apiKeys (or api.auth.existingSecret, or Vault injection) is required — this chart ships no default credentials (REQ-OPS-006)" -}}
{{- end -}}
{{- if and (gt (int .Values.agent.replicas) 0) (not (or .Values.agent.auth.existingSecret .Values.agent.auth.apiKey)) -}}
{{- fail "agent.auth.apiKey (or agent.auth.existingSecret) is required when agent.replicas > 0 — this chart ships no default credentials (REQ-OPS-006)" -}}
{{- end -}}
{{- end -}}
