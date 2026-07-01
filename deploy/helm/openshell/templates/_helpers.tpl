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
Create the name of the service account assigned to sandbox pods
*/}}
{{- define "openshell.sandboxServiceAccountName" -}}
{{- if .Values.sandboxServiceAccount.create }}
{{- default (printf "%s-sandbox" (include "openshell.fullname" .) | trunc 63 | trimSuffix "-") .Values.sandboxServiceAccount.name }}
{{- else }}
{{- default "default" .Values.sandboxServiceAccount.name }}
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

{{/*
Namespace where sandbox pods are created. An explicit
.Values.server.sandboxNamespace is used verbatim. Otherwise it defaults to
.Release.Namespace so `helm install -n my-ns` works without extra overrides.
*/}}
{{- define "openshell.sandboxNamespace" -}}
{{- .Values.server.sandboxNamespace | default .Release.Namespace -}}
{{- end }}

{{/*
Name of the Secret holding gateway-minted sandbox JWT signing material.
*/}}
{{- define "openshell.sandboxJwtSecretName" -}}
{{- .Values.server.sandboxJwt.signingSecretName | default (printf "%s-jwt-keys" (include "openshell.fullname" .)) -}}
{{- end }}

{{/*
gRPC endpoint sandbox pods use to call back into the gateway. An explicit
.Values.server.grpcEndpoint is used verbatim. Otherwise it is derived from
the in-cluster Service DNS, release namespace, service port, and disableTls
flag — so the default value works for any release name or namespace without
override.
*/}}
{{/*
Supervisor sideload method. When supervisor.sideloadMethod is set, use it
verbatim. Otherwise auto-detect from the cluster version: the ImageVolume
feature gate is enabled by default starting in K8s v1.35 (GA in v1.36).
Clusters on v1.33-v1.34 can opt in by setting sideloadMethod explicitly
after enabling the feature gate.
*/}}
{{- define "openshell.supervisorSideloadMethod" -}}
{{- if .Values.supervisor.sideloadMethod -}}
{{- .Values.supervisor.sideloadMethod -}}
{{- else -}}
{{- if semverCompare ">=1.35-0" .Capabilities.KubeVersion.Version -}}
image-volume
{{- else -}}
init-container
{{- end -}}
{{- end -}}
{{- end }}

{{- define "openshell.grpcEndpoint" -}}
{{- if .Values.server.grpcEndpoint -}}
{{- .Values.server.grpcEndpoint -}}
{{- else -}}
{{- $scheme := ternary "http" "https" (default false .Values.server.disableTls) -}}
{{- printf "%s://%s.%s.svc.cluster.local:%d" $scheme (include "openshell.fullname" .) .Release.Namespace (int .Values.service.port) -}}
{{- end -}}
{{- end }}

{{/*
Default server certificate DNS SANs derived from the release name and namespace.
Returns a YAML list. Append extra SANs from values with range loops.
*/}}
{{- define "openshell.defaultServerDnsNames" -}}
{{- $name := include "openshell.fullname" . -}}
{{- $ns := .Release.Namespace -}}
{{- list $name
      (printf "%s.%s.svc" $name $ns)
      (printf "%s.%s.svc.cluster.local" $name $ns)
      "localhost"
      (printf "%s.localhost" $name)
      (printf "*.%s.localhost" $name)
      "host.docker.internal"
      "host.containers.internal"
  | toYaml }}
{{- end }}

{{/*
Gateway workload kind. StatefulSet is the default because the default SQLite
database requires persistent per-pod storage.
*/}}
{{- define "openshell.workloadKind" -}}
{{- $workload := .Values.workload | default dict -}}
{{- if not (kindIs "map" $workload) -}}
{{- fail "workload must be a map with kind and allowMultiReplicaStatefulSet fields." -}}
{{- end -}}
{{- default "statefulset" (get $workload "kind") | lower -}}
{{- end }}

{{/*
Validate chart values that Helm would otherwise accept silently.
*/}}
{{- define "openshell.validateValues" -}}
{{- $workloadKind := include "openshell.workloadKind" . -}}
{{- $workload := .Values.workload | default dict -}}
{{- $replicaCount := int (default 1 .Values.replicaCount) -}}
{{- $oidcIssuer := default "" .Values.server.oidc.issuer -}}
{{- $oidcAdminRole := default "" .Values.server.oidc.adminRole -}}
{{- $oidcUserRole := default "" .Values.server.oidc.userRole -}}
{{- $oidcAdminRoleSet := ne $oidcAdminRole "" -}}
{{- $oidcUserRoleSet := ne $oidcUserRole "" -}}
{{- if and (hasKey .Values "postgres") (kindIs "map" .Values.postgres) (hasKey .Values.postgres "enabled") -}}
{{- fail "postgres.enabled was removed; the OpenShell chart no longer deploys PostgreSQL. Provision PostgreSQL separately and set server.externalDbSecret to a Secret containing a PostgreSQL URI." -}}
{{- end -}}
{{- if and $oidcIssuer (ne $oidcAdminRoleSet $oidcUserRoleSet) -}}
{{- fail "server.oidc.adminRole and server.oidc.userRole must either both be set for OIDC RBAC or both be empty for authentication-only mode." -}}
{{- end -}}
{{- if and $oidcIssuer (not $oidcAdminRoleSet) (not .Values.server.auth.allowOidcAuthOnly) -}}
{{- fail "OIDC authentication-only mode authorizes any valid issuer token. Set server.oidc.adminRole and server.oidc.userRole for RBAC, or set server.auth.allowOidcAuthOnly=true to opt in explicitly." -}}
{{- end -}}
{{- if not (or (eq $workloadKind "statefulset") (eq $workloadKind "deployment")) -}}
{{- fail "workload.kind must be one of: statefulset, deployment." -}}
{{- end -}}
{{- if and (eq $workloadKind "deployment") (not .Values.server.externalDbSecret) -}}
{{- fail "workload.kind=deployment requires server.externalDbSecret; use workload.kind=statefulset for the default SQLite database." -}}
{{- end -}}
{{- if and (gt $replicaCount 1) (not .Values.server.externalDbSecret) -}}
{{- fail "replicaCount > 1 requires server.externalDbSecret; multiple gateway replicas cannot share the default per-pod SQLite database." -}}
{{- end -}}
{{- if and (eq $workloadKind "statefulset") (gt $replicaCount 1) (not (get $workload "allowMultiReplicaStatefulSet" | default false)) -}}
{{- fail "replicaCount > 1 with workload.kind=statefulset requires workload.allowMultiReplicaStatefulSet=true; use workload.kind=deployment for external database-backed multi-replica gateways." -}}
{{- end -}}
{{- end }}
