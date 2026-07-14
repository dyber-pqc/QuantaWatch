{{/*
Expand the name of the chart.
*/}}
{{- define "quantawatch.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to
this length (by the DNS naming spec).
*/}}
{{- define "quantawatch.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "quantawatch.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "quantawatch.labels" -}}
helm.sh/chart: {{ include "quantawatch.chart" . }}
{{ include "quantawatch.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels for the gateway.
*/}}
{{- define "quantawatch.selectorLabels" -}}
app.kubernetes.io/name: {{ include "quantawatch.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Dashboard labels.
*/}}
{{- define "quantawatch.dashboard.labels" -}}
helm.sh/chart: {{ include "quantawatch.chart" . }}
{{ include "quantawatch.dashboard.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels for the dashboard.
*/}}
{{- define "quantawatch.dashboard.selectorLabels" -}}
app.kubernetes.io/name: {{ include "quantawatch.name" . }}-dashboard
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Gateway image reference (uses appVersion as default tag).
*/}}
{{- define "quantawatch.gateway.image" -}}
{{- $tag := default .Chart.AppVersion .Values.gateway.image.tag -}}
{{- printf "%s:%s" .Values.gateway.image.repository $tag -}}
{{- end }}

{{/*
Dashboard image reference (uses appVersion as default tag).
*/}}
{{- define "quantawatch.dashboard.image" -}}
{{- $tag := default .Chart.AppVersion .Values.dashboard.image.tag -}}
{{- printf "%s:%s" .Values.dashboard.image.repository $tag -}}
{{- end }}
