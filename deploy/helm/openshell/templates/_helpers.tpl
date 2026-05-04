{{/*
Expand the name of the chart.
*/}}
{{- define "openshell.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "openshell.fullname" -}}
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
{{- define "openshell.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "openshell.labels" -}}
helm.sh/chart: {{ include "openshell.chart" . }}
{{ include "openshell.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "openshell.selectorLabels" -}}
app.kubernetes.io/name: {{ include "openshell.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "openshell.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "openshell.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Gateway image reference. Uses image.tag when set; falls back to .Chart.AppVersion
so a released chart automatically pulls the matching image without extra overrides.
*/}}
{{- define "openshell.image" -}}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) }}
{{- end }}

{{/*
Supervisor image reference. Same appVersion fallback as openshell.image so
the supervisor and gateway images stay in sync across releases.
*/}}
{{- define "openshell.supervisorImage" -}}
{{- printf "%s:%s" .Values.supervisor.image.repository (.Values.supervisor.image.tag | default .Chart.AppVersion) }}
{{- end }}

{{/*
Namespaced Issuer (selfSigned) for cert-manager CA bootstrap.
*/}}
{{- define "openshell.issuerSelfSigned" -}}
{{- printf "%s-selfsigned" (include "openshell.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
