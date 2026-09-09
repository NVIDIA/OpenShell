{{/*
Expand the name of the chart.
*/}}
{{- define "openshell-workspace.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "openshell-workspace.fullname" -}}
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
Common labels.
*/}}
{{- define "openshell-workspace.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/name: {{ include "openshell-workspace.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Validate required cross-namespace gateway identity values.
*/}}
{{- define "openshell-workspace.validateValues" -}}
{{- $gatewayServiceAccountName := required "gateway.serviceAccount.name is required" .Values.gateway.serviceAccount.name -}}
{{- $gatewayServiceAccountNamespace := required "gateway.serviceAccount.namespace is required" .Values.gateway.serviceAccount.namespace -}}
{{- $sandboxServiceAccountName := required "sandboxServiceAccount.name is required" .Values.sandboxServiceAccount.name -}}
{{- end }}
