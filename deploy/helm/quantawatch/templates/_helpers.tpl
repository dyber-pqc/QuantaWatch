{{/* Expand the name of the chart. */}}
{{- define "quantawatch.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Fully qualified app name. */}}
{{- define "quantawatch.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "quantawatch.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Common labels */}}
{{- define "quantawatch.labels" -}}
helm.sh/chart: {{ include "quantawatch.chart" . }}
{{ include "quantawatch.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/* Selector labels */}}
{{- define "quantawatch.selectorLabels" -}}
app.kubernetes.io/name: {{ include "quantawatch.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* Gateway image ref (repository:tag, tag defaults to appVersion) */}}
{{- define "quantawatch.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}

{{/* Dashboard image ref */}}
{{- define "quantawatch.dashboardImage" -}}
{{- printf "%s:%s" .Values.dashboard.image.repository (default .Chart.AppVersion .Values.dashboard.image.tag) -}}
{{- end -}}

{{/* FortressQL resource name (StatefulSet, Service, Secret) */}}
{{- define "quantawatch.fortressqlName" -}}
{{- printf "%s-fortressql" (include "quantawatch.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* FortressQL image ref (repository:tag, tag defaults to "latest") */}}
{{- define "quantawatch.fortressqlImage" -}}
{{- printf "%s:%s" .Values.fortressql.image.repository (default "latest" .Values.fortressql.image.tag) -}}
{{- end -}}

{{/*
Store path handed to the gateway via the QW_STORE_PATH env var. When FortressQL
is enabled, this is a postgres:// URL to the in-cluster StatefulSet over
PQC-capable TLS; the password is injected by Kubernetes via $(FORTRESSQL_PASSWORD)
(a secretKeyRef defined earlier in the container's env), so it never appears in
the ConfigMap. Otherwise it's the local SQLite directory.
*/}}
{{- define "quantawatch.storePath" -}}
{{- if .Values.fortressql.enabled -}}
postgres://{{ .Values.fortressql.auth.username }}:$(FORTRESSQL_PASSWORD)@{{ include "quantawatch.fortressqlName" . }}:5432/{{ .Values.fortressql.auth.database }}?sslmode=require
{{- else -}}
{{- .Values.store.path -}}
{{- end -}}
{{- end -}}

{{/* True (non-empty) when the store is shared across replicas (FortressQL, or
     a postgres:// store path) rather than a per-pod SQLite file. */}}
{{- define "quantawatch.sharedStore" -}}
{{- if or .Values.fortressql.enabled (hasPrefix "postgres" .Values.store.path) -}}true{{- end -}}
{{- end -}}

{{/* True (non-empty) when a shared signing seed is supplied, so every replica
     derives the same ML-DSA identity (no per-pod key files). */}}
{{- define "quantawatch.hasSeed" -}}
{{- if .Values.secretEnv.QW_GATEWAY_SEED -}}true{{- end -}}
{{- end -}}

{{/* True (non-empty) when the gateway keeps NO local state: shared store (DB
     holds inventory/sessions/audit) AND a shared seed (identity from the
     Secret). Such a gateway needs no PVC and can run many replicas. */}}
{{- define "quantawatch.stateless" -}}
{{- if and (include "quantawatch.sharedStore" .) (include "quantawatch.hasSeed" .) -}}true{{- end -}}
{{- end -}}
