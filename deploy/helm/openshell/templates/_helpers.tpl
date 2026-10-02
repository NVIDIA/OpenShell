# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

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
Whether this chart owns workspace-scoped resources. Missing legacy values
default to enabled so upgrades with --reuse-values preserve the old topology.
*/}}
{{- define "openshell.workspaceResourcesEnabled" -}}
{{- $workspaceResources := .Values.workspaceResources | default dict -}}
{{- $enabled := true -}}
{{- if hasKey $workspaceResources "enabled" -}}
{{- $enabled = get $workspaceResources "enabled" -}}
{{- end -}}
{{- if $enabled -}}true{{- end -}}
{{- end }}

{{/*
Whether this chart owns gateway RBAC objects. Missing legacy values default to
enabled so upgrades with --reuse-values preserve the old topology.
*/}}
{{- define "openshell.rbacCreate" -}}
{{- $rbac := .Values.rbac | default dict -}}
{{- $create := true -}}
{{- if hasKey $rbac "create" -}}
{{- $create = get $rbac "create" -}}
{{- end -}}
{{- if $create -}}true{{- end -}}
{{- end }}

{{/*
The rbac.clusterScoped values map, tolerating missing legacy values.
*/}}
{{- define "openshell.clusterScopedRbacValues" -}}
{{- $rbac := .Values.rbac | default dict -}}
{{- $clusterScoped := dict -}}
{{- if hasKey $rbac "clusterScoped" -}}
{{- $clusterScoped = get $rbac "clusterScoped" | default dict -}}
{{- end -}}
{{- toYaml $clusterScoped -}}
{{- end }}

{{/*
Whether this chart owns the cluster-scoped ClusterRole and ClusterRoleBinding.
Disable for a namespace-admin install where a cluster-admin applies them
separately. Missing legacy values default to enabled.
*/}}
{{- define "openshell.clusterRbacCreate" -}}
{{- if include "openshell.rbacCreate" . -}}
{{- $clusterScoped := include "openshell.clusterScopedRbacValues" . | fromYaml -}}
{{- $create := true -}}
{{- if hasKey $clusterScoped "create" -}}
{{- $create = get $clusterScoped "create" -}}
{{- end -}}
{{- if $create -}}true{{- end -}}
{{- end -}}
{{- end }}

{{/*
Name of the gateway ClusterRole. The release namespace is part of the default
name so multiple releases on one cluster do not collide.
*/}}
{{- define "openshell.clusterRoleName" -}}
{{- $clusterScoped := include "openshell.clusterScopedRbacValues" . | fromYaml -}}
{{- $default := printf "%s-node-reader-%s" (include "openshell.fullname" .) .Release.Namespace -}}
{{- default $default (get $clusterScoped "clusterRoleName") -}}
{{- end }}

{{/*
Name of the gateway ClusterRoleBinding.
*/}}
{{- define "openshell.clusterRoleBindingName" -}}
{{- $clusterScoped := include "openshell.clusterScopedRbacValues" . | fromYaml -}}
{{- $default := printf "%s-node-reader-%s" (include "openshell.fullname" .) .Release.Namespace -}}
{{- default $default (get $clusterScoped "clusterRoleBindingName") -}}
{{- end }}

{{/* Gateway image reference. A digest takes precedence over a tag. */}}
{{- define "openshell.image" -}}
{{- $image := .Values.gateway.image -}}
{{- $global := .Values.global.image -}}
{{- $registry := $image.registry | default $global.registry -}}
{{- $repository := ternary (printf "%s/%s" $registry $image.repository) $image.repository (ne $registry "") -}}
{{- if $image.digest -}}
{{- printf "%s@%s" $repository $image.digest -}}
{{- else -}}
{{- printf "%s:%s" $repository ($image.tag | default $global.tag | default .Chart.AppVersion) -}}
{{- end }}
{{- end }}

{{/* Sandbox image reference. A digest takes precedence over a tag. */}}
{{- define "openshell.sandboxImage" -}}
{{- $image := .Values.sandbox.image -}}
{{- if $image.digest -}}
{{- printf "%s@%s" $image.repository $image.digest -}}
{{- else -}}
{{- printf "%s:%s" $image.repository ($image.tag | default "latest") -}}
{{- end }}
{{- end }}

{{/* Official sandbox runtime repository used by the gateway's built-in default. */}}
{{- define "openshell.defaultSandboxRuntimeRepository" -}}
ghcr.io/nvidia/openshell/sandbox
{{- end }}

{{/* Whether Helm must propagate a sandbox runtime image override. */}}
{{- define "openshell.sandboxRuntimeImageOverrideEnabled" -}}
{{- $defaultRepository := include "openshell.defaultSandboxRuntimeRepository" . -}}
{{- $global := .Values.global.image -}}
{{- $registry := .Values.sandboxRuntime.image.registry | default $global.registry -}}
{{- $repository := ternary (printf "%s/%s" $registry .Values.sandboxRuntime.image.repository) .Values.sandboxRuntime.image.repository (ne $registry "") -}}
{{- if or (ne $repository $defaultRepository) .Values.sandboxRuntime.image.tag .Values.sandboxRuntime.image.digest .Values.global.image.tag -}}true{{- end -}}
{{- end }}

{{/* Sandbox runtime image override. */}}
{{- define "openshell.sandboxRuntimeImage" -}}
{{- $global := .Values.global.image -}}
{{- $registry := .Values.sandboxRuntime.image.registry | default $global.registry -}}
{{- $repository := ternary (printf "%s/%s" $registry .Values.sandboxRuntime.image.repository) .Values.sandboxRuntime.image.repository (ne $registry "") -}}
{{- if .Values.sandboxRuntime.image.digest -}}
{{- printf "%s@%s" $repository .Values.sandboxRuntime.image.digest -}}
{{- else -}}
{{- $tag := .Values.sandboxRuntime.image.tag | default $global.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" $repository $tag -}}
{{- end -}}
{{- end }}

{{/*
Whether the gateway listener should verify client certificates (mTLS).
An explicit empty server.tls.clientCaSecretName disables client-CA wiring in
both gateway.toml and the workload, overriding built-in PKI and cert-manager
defaults.
*/}}
{{- define "openshell.gatewayClientCaEnabled" -}}
{{- if .Values.server.disableTls -}}
{{- else if not .Values.server.tls.enableMtls -}}
{{- else if eq .Values.server.tls.clientCaSecretName "" -}}
{{- else -}}
true
{{- end -}}
{{- end -}}

{{/* Supervisor image override. */}}
{{- define "openshell.supervisorImage" -}}
{{- $global := .Values.global.image -}}
{{- $registry := .Values.supervisor.image.registry | default $global.registry -}}
{{- $repository := ternary (printf "%s/%s" $registry .Values.supervisor.image.repository) .Values.supervisor.image.repository (ne $registry "") -}}
{{- if .Values.supervisor.image.digest -}}
{{- printf "%s@%s" $repository .Values.supervisor.image.digest -}}
{{- else -}}
{{- $tag := .Values.supervisor.image.tag | default $global.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" $repository $tag -}}
{{- end }}
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
Secrets in the sandbox namespace whose contents the Kubernetes driver stages
into per-generation Secrets in workspace namespaces, as a JSON array. Empty in
shared workspace mode.
*/}}
{{- define "openshell.workspaceSecretSourceNames" -}}
{{- $workspaceMode := .Values.server.drivers.kubernetes.workspaceMode | default "shared" -}}
{{- $names := list -}}
{{- if and (ne $workspaceMode "shared") (not .Values.server.disableTls) -}}
{{- $names = append $names .Values.server.tls.clientTlsSecretName -}}
{{- end -}}
{{- if eq $workspaceMode "managed" -}}
{{- range .Values.server.sandboxImagePullSecrets -}}
{{- if .name -}}
{{- $names = append $names .name -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- uniq $names | toJson -}}
{{- end }}

{{/*
Namespace where Kubernetes Secret-backed provider credentials live.
*/}}
{{- define "openshell.credentialKubernetesSecretsNamespace" -}}
{{- $gatewayConfig := .Values.gatewayConfig | default dict -}}
{{- $config := get $gatewayConfig "openshell.credential_drivers.kubernetes-secrets" | default dict -}}
{{- $legacy := .Values.server.credentialDrivers.kubernetesSecrets | default dict -}}
{{- get $config "namespace" | default (get $legacy "namespace") | default .Release.Namespace -}}
{{- end }}

{{/* Whether a credential driver is enabled in the generic gateway config. */}}
{{- define "openshell.credentialDriverEnabled" -}}
{{- $root := index . 0 -}}
{{- $driver := index . 1 -}}
{{- $gatewayConfig := $root.Values.gatewayConfig | default dict -}}
{{- $gateway := get $gatewayConfig "openshell.gateway" | default dict -}}
{{- $configuredDrivers := get $gateway "credential_drivers" -}}
{{- if and (hasKey $gateway "credential_drivers") (ne $configuredDrivers nil) -}}
{{- if has $driver ($configuredDrivers | default list) -}}true{{- end -}}
{{- else if eq $driver "kubernetes-secrets" -}}
{{- if $root.Values.server.credentialDrivers.kubernetesSecrets.enabled -}}true{{- end -}}
{{- else if eq $driver "vault" -}}
{{- if $root.Values.server.credentialDrivers.vault.enabled -}}true{{- end -}}
{{- end -}}
{{- end }}

{{/*
Name of the Secret holding the default credential storage key-encryption key.
When server.credentialStorage.existingSecret is set, returns that name instead
of the chart-generated name (for GitOps / helm-template workflows).
*/}}
{{- define "openshell.credentialStorageKeyEncryptionKeySecretName" -}}
{{- if .Values.server.credentialStorage.existingSecret -}}
{{- .Values.server.credentialStorage.existingSecret -}}
{{- else -}}
{{- printf "%s-credential-storage-key-encryption-key" (include "openshell.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end }}

{{/*
Key inside the default credential storage key-encryption key Secret.
*/}}
{{- define "openshell.credentialStorageKeyEncryptionKeySecretKey" -}}
key-encryption-key
{{- end }}

{{/*
Gateway environment variable used to pass the default credential storage key-encryption key.
*/}}
{{- define "openshell.credentialStorageKeyEncryptionKeyEnvName" -}}
OPENSHELL_GATEWAY_CREDENTIAL_KEY_ENCRYPTION_KEY
{{- end }}

{{/*
Name of the Secret holding gateway-minted sandbox JWT signing material.
*/}}
{{- define "openshell.sandboxJwtSecretName" -}}
{{- .Values.server.sandboxJwt.signingSecretName | default (printf "%s-jwt-keys" (include "openshell.fullname" .)) -}}
{{- end }}

{{- define "openshell.peerServiceName" -}}
{{- printf "%s-peer" (include "openshell.fullname" .) -}}
{{- end }}

{{/*
gRPC endpoint sandbox pods use to call back into the gateway. An explicit
.Values.server.grpcEndpoint is used verbatim. Otherwise it is derived from
the in-cluster Service DNS, release namespace, service port, and disableTls
flag — so the default value works for any release name or namespace without
override.
*/}}
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
Name of the ConfigMap holding the backend CA for BackendTLSPolicy validation.
*/}}
{{- define "openshell.backendCaConfigMapName" -}}
{{- .Values.grpcRoute.backendTLSPolicy.caCertificateConfigMapName | default (printf "%s-backend-ca" (include "openshell.fullname" .)) -}}
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
Translate chart image pull policy values to the canonical gateway vocabulary.
The Kubernetes spellings remain accepted so existing values files continue to
work across the schema-v2 chart upgrade.
*/}}
{{- define "openshell.canonicalImagePullPolicy" -}}
{{- $policy := printf "%v" . -}}
{{- if eq $policy "Always" -}}
always
{{- else if eq $policy "IfNotPresent" -}}
if_not_present
{{- else if eq $policy "Never" -}}
never
{{- else if has $policy (list "always" "if_not_present" "never") -}}
{{- $policy -}}
{{- else -}}
{{- fail (printf "image pull policy %q must be one of: always, if_not_present, never, Always, IfNotPresent, Never" $policy) -}}
{{- end -}}
{{- end }}

{{/*
Validate a non-empty, user-provided Kubernetes Secret name. Secret data never
passes through Helm values into gateway.toml; only this reference is rendered.
*/}}
{{- define "openshell.validateSecretReference" -}}
{{- $path := index . 0 -}}
{{- $name := index . 1 -}}
{{- if and (ne $name nil) (ne $name "") -}}
{{- if not (kindIs "string" $name) -}}
{{- fail (printf "%s must be a Kubernetes Secret name, got %s" $path (kindOf $name)) -}}
{{- end -}}
{{- if gt (len $name) 253 -}}
{{- fail (printf "%s must be no more than 253 characters" $path) -}}
{{- end -}}
{{- if not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$" $name) -}}
{{- fail (printf "%s must be a valid Kubernetes Secret name" $path) -}}
{{- end -}}
{{- end -}}
{{- end }}

{{/*
Return the effective Kubernetes driver configuration as YAML. Schema-v2
gatewayConfig fields take precedence; deprecated 0.1.x aliases fill only
absent fields so every chart consumer observes the same configuration.
*/}}
{{- define "openshell.effectiveKubernetesConfig" -}}
{{- $gatewayConfig := deepCopy (.Values.gatewayConfig | default dict) -}}
{{- $kubernetes := get $gatewayConfig "openshell.drivers.kubernetes" | default dict -}}
{{- $legacySandbox := .Values.sandboxRuntime.image | default dict -}}
{{- if and (include "openshell.sandboxRuntimeImageOverrideEnabled" .) (not (hasKey $kubernetes "sandbox_runtime_image")) -}}
{{- $_ := set $kubernetes "sandbox_runtime_image" (include "openshell.sandboxRuntimeImage" .) -}}
{{- end -}}
{{- $legacySandboxImage := .Values.sandbox.image | default dict -}}
{{- $legacySandboxPullPolicy := get $legacySandboxImage "pullPolicy" | default .Values.global.image.pullPolicy -}}
{{- if and $legacySandboxPullPolicy (not (hasKey $kubernetes "image_pull_policy")) -}}
{{- $_ := set $kubernetes "image_pull_policy" (include "openshell.canonicalImagePullPolicy" $legacySandboxPullPolicy) -}}
{{- end -}}
{{- $legacySandboxRuntimePullPolicy := get $legacySandbox "pullPolicy" | default .Values.global.image.pullPolicy -}}
{{- if and $legacySandboxRuntimePullPolicy (not (hasKey $kubernetes "sandbox_runtime_image_pull_policy")) -}}
{{- $_ := set $kubernetes "sandbox_runtime_image_pull_policy" (include "openshell.canonicalImagePullPolicy" $legacySandboxRuntimePullPolicy) -}}
{{- end -}}
{{- $legacySupervisor := .Values.supervisor.image | default dict -}}
{{- $legacySupervisorImage := include "openshell.supervisorImage" . -}}
{{- $defaultSupervisorImage := printf "ghcr.io/nvidia/openshell/supervisor:%s" .Chart.AppVersion -}}
{{- if and (ne $legacySupervisorImage $defaultSupervisorImage) (not (hasKey $kubernetes "supervisor_image")) -}}
{{- $_ := set $kubernetes "supervisor_image" $legacySupervisorImage -}}
{{- end -}}
{{- $legacySupervisorPullPolicy := get $legacySupervisor "pullPolicy" | default .Values.global.image.pullPolicy -}}
{{- if and $legacySupervisorPullPolicy (not (hasKey $kubernetes "supervisor_image_pull_policy")) -}}
{{- $_ := set $kubernetes "supervisor_image_pull_policy" (include "openshell.canonicalImagePullPolicy" $legacySupervisorPullPolicy) -}}
{{- end -}}
{{- $legacyRuntime := .Values.supervisor.sandboxRuntime | default dict -}}
{{- $runtimeConfig := get $kubernetes "sandbox_runtime" | default dict -}}
{{- if and (ne (int (get $legacyRuntime "boundaryPort" | default 5500)) 5500) (not (hasKey $runtimeConfig "boundary_port")) -}}
{{- $_ := set $runtimeConfig "boundary_port" (int (get $legacyRuntime "boundaryPort")) -}}
{{- end -}}
{{- $_ := set $kubernetes "sandbox_runtime" $runtimeConfig -}}
{{- $legacyProxy := .Values.upstreamProxy | default dict -}}
{{- range $legacyKey, $runtimeKey := dict "url" "https_proxy" "noProxy" "no_proxy" "authAllowInsecure" "proxy_auth_allow_insecure" "connectByHostname" "proxy_connect_by_hostname" -}}
{{- if and (get $legacyProxy $legacyKey) (not (hasKey $kubernetes $runtimeKey)) -}}
{{- $_ := set $kubernetes $runtimeKey (get $legacyProxy $legacyKey) -}}
{{- end -}}
{{- end -}}
{{- $legacyProxyAuth := get $legacyProxy "authSecret" | default dict -}}
{{- if and (get $legacyProxyAuth "name") (not (hasKey $kubernetes "proxy_auth_secret_name")) -}}{{- $_ := set $kubernetes "proxy_auth_secret_name" (get $legacyProxyAuth "name") -}}{{- end -}}
{{- if and (get $legacyProxyAuth "key") (not (hasKey $kubernetes "proxy_auth_secret_key")) -}}{{- $_ := set $kubernetes "proxy_auth_secret_key" (get $legacyProxyAuth "key") -}}{{- end -}}
{{- $legacyProxyCa := get $legacyProxy "caBundle" | default dict -}}
{{- if and (get $legacyProxyCa "configMapName") (not (hasKey $kubernetes "proxy_ca_bundle")) -}}
{{- $_ := set $kubernetes "proxy_ca_bundle" "/etc/openshell-tls/proxy-ca/ca.crt" -}}
{{- end -}}
{{- $legacyKubernetes := .Values.server.drivers.kubernetes | default dict -}}
{{- $legacyServer := .Values.server | default dict -}}
{{- if not (hasKey $kubernetes "allow_driver_config") -}}{{- $_ := set $kubernetes "allow_driver_config" (get $legacyKubernetes "allowDriverConfig" | default false) -}}{{- end -}}
{{- if and (ne (get $legacyKubernetes "workspaceMode" | default "shared") "shared") (not (hasKey $kubernetes "workspace_mode")) -}}
{{- $_ := set $kubernetes "workspace_mode" (get $legacyKubernetes "workspaceMode") -}}
{{- end -}}
{{- range $legacyKey, $runtimeKey := dict "operatorNamespaceLabel" "operator_namespace_label" "operatorNamespaceFile" "operator_namespace_file" -}}
{{- if and (get $legacyKubernetes $legacyKey) (not (hasKey $kubernetes $runtimeKey)) -}}
{{- $_ := set $kubernetes $runtimeKey (get $legacyKubernetes $legacyKey) -}}
{{- end -}}
{{- end -}}
{{- if not (hasKey $kubernetes "resource_admission") -}}
{{- $legacyAdmission := get $legacyKubernetes "resourceAdmission" | default dict -}}
{{- $admission := dict -}}
{{- if hasKey $legacyAdmission "enabled" -}}{{- $_ := set $admission "enabled" (get $legacyAdmission "enabled") -}}{{- end -}}
{{- if and (hasKey $legacyAdmission "requiredLabels") (ne (get $legacyAdmission "requiredLabels") nil) -}}{{- $_ := set $admission "required_labels" (deepCopy (get $legacyAdmission "requiredLabels")) -}}{{- end -}}
{{- $_ := set $kubernetes "resource_admission" $admission -}}
{{- end -}}
{{- if and (get $legacyServer "enableUserNamespaces") (not (hasKey $kubernetes "enable_user_namespaces")) -}}{{- $_ := set $kubernetes "enable_user_namespaces" true -}}{{- end -}}
{{- if and (get $legacyServer "hostGatewayIP") (not (hasKey $kubernetes "host_gateway_ip")) -}}{{- $_ := set $kubernetes "host_gateway_ip" (get $legacyServer "hostGatewayIP") -}}{{- end -}}
{{- if not (hasKey $kubernetes "namespace") -}}{{- $_ := set $kubernetes "namespace" (include "openshell.sandboxNamespace" .) -}}{{- end -}}
{{- if not (hasKey $kubernetes "default_image") -}}{{- $_ := set $kubernetes "default_image" (include "openshell.sandboxImage" .) -}}{{- end -}}
{{- if not (hasKey $kubernetes "gateway_id") -}}{{- $_ := set $kubernetes "gateway_id" (get (.Values.server.sandboxJwt | default dict) "gatewayId" | default (include "openshell.fullname" .)) -}}{{- end -}}
{{- if not (hasKey $kubernetes "grpc_endpoint") -}}{{- $_ := set $kubernetes "grpc_endpoint" (include "openshell.grpcEndpoint" .) -}}{{- end -}}
{{- if not (hasKey $kubernetes "service_account_name") -}}{{- $_ := set $kubernetes "service_account_name" (include "openshell.sandboxServiceAccountName" .) -}}{{- end -}}
{{- if not (hasKey $kubernetes "sa_token_ttl_secs") -}}{{- $_ := set $kubernetes "sa_token_ttl_secs" (get (.Values.server.sandboxJwt | default dict) "k8sSaTokenTtlSecs" | default 3600) -}}{{- end -}}
{{- if not (hasKey $kubernetes "image_pull_secrets") -}}
{{- $imagePullSecrets := list -}}{{- range (get $legacyServer "sandboxImagePullSecrets" | default list) }}{{- if .name }}{{- $imagePullSecrets = append $imagePullSecrets .name }}{{- end }}{{- end -}}
{{- if $imagePullSecrets }}{{- $_ := set $kubernetes "image_pull_secrets" $imagePullSecrets -}}{{- end -}}
{{- end -}}
{{- range $legacyKey, $runtimeKey := dict "workspaceDefaultStorageSize" "workspace_default_storage_size" "workspaceStorageClass" "workspace_storage_class" "defaultRuntimeClassName" "default_runtime_class_name" -}}
{{- if and (get $legacyServer $legacyKey) (not (hasKey $kubernetes $runtimeKey)) -}}{{- $_ := set $kubernetes $runtimeKey (get $legacyServer $legacyKey) -}}{{- end -}}
{{- end -}}
{{- $legacySpiffe := .Values.server.providerTokenGrants.spiffe | default dict -}}
{{- if and (get $legacySpiffe "enabled") (not (hasKey $kubernetes "provider_spiffe_workload_api_socket_path")) -}}
{{- $_ := set $kubernetes "provider_spiffe_workload_api_socket_path" (get $legacySpiffe "workloadApiSocketPath") -}}
{{- end -}}
{{/* Keep the rendered default configuration stable without making defaults look
like user-supplied schema-v2 fields during compatibility resolution. */}}
{{- if not (hasKey $kubernetes "workspace_mode") -}}{{- $_ := set $kubernetes "workspace_mode" "shared" -}}{{- end -}}
{{- if not (hasKey $kubernetes "supervisor_image") -}}{{- $_ := set $kubernetes "supervisor_image" (include "openshell.supervisorImage" .) -}}{{- end -}}
{{- if not (hasKey $runtimeConfig "boundary_port") -}}{{- $_ := set $runtimeConfig "boundary_port" 5500 -}}{{- end -}}
{{- $_ := set $kubernetes "sandbox_runtime" $runtimeConfig -}}
{{- toYaml $kubernetes -}}
{{- end }}

{{/*
Validate chart values that Helm would otherwise accept silently.
*/}}
{{- define "openshell.validateValues" -}}
{{- $workloadKind := include "openshell.workloadKind" . -}}
{{- $workload := .Values.workload | default dict -}}
{{- $replicaCount := int (default 1 .Values.replicaCount) -}}
{{- if and (hasKey .Values "postgres") (kindIs "map" .Values.postgres) (hasKey .Values.postgres "enabled") -}}
{{- fail "postgres.enabled was removed; the OpenShell chart no longer deploys PostgreSQL. Provision PostgreSQL separately and set server.externalDbSecret to a Secret containing a PostgreSQL URI." -}}
{{- end -}}
{{- if and .Values.certManager.serverIssuerRef.name (not .Values.certManager.enabled) -}}
{{- fail "certManager.serverIssuerRef.name is set but certManager.enabled is false — the external server certificate, its Secret mount, and the gateway TLS configuration all require cert-manager to be enabled. Set certManager.enabled=true or remove certManager.serverIssuerRef.name." -}}
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
{{- include "openshell.validateSecretReference" (list "server.externalDbSecret" .Values.server.externalDbSecret) -}}
{{- include "openshell.validateSecretReference" (list "server.credentialStorage.existingSecret" .Values.server.credentialStorage.existingSecret) -}}
{{- include "openshell.validateSecretReference" (list "server.sandboxJwt.signingSecretName" .Values.server.sandboxJwt.signingSecretName) -}}
{{- include "openshell.validateSecretReference" (list "server.tls.certSecretName" .Values.server.tls.certSecretName) -}}
{{- include "openshell.validateSecretReference" (list "upstreamProxy.authSecret.name" .Values.upstreamProxy.authSecret.name) -}}
{{- $gatewayConfig := .Values.gatewayConfig | default dict -}}
{{- $gateway := get $gatewayConfig "openshell.gateway" | default dict -}}
{{- $credentialDrivers := get $gateway "credential_drivers" -}}
{{- if and (hasKey $gateway "credential_drivers") (ne $credentialDrivers nil) -}}
{{- if eq (len $credentialDrivers) 0 -}}
{{- fail "gatewayConfig.openshell.gateway.credential_drivers must select exactly one backend or be omitted/null to use the chart default" -}}
{{- end -}}
{{- if gt (len $credentialDrivers) 1 -}}
{{- fail "gatewayConfig.openshell.gateway.credential_drivers may select only one backend" -}}
{{- end -}}
{{- end -}}
{{- $kubernetesConfig := include "openshell.effectiveKubernetesConfig" . | fromYaml -}}
{{- include "openshell.validateSecretReference" (list "gatewayConfig.openshell.drivers.kubernetes.proxy_auth_secret_name" (get $kubernetesConfig "proxy_auth_secret_name")) -}}
{{- $workspaceMode := get $kubernetesConfig "workspace_mode" | default "shared" -}}
{{- if not (has $workspaceMode (list "shared" "managed" "operator")) -}}
{{- fail "gatewayConfig.openshell.drivers.kubernetes.workspace_mode must be one of: shared, managed, operator." -}}
{{- end -}}
{{- if kindIs "invalid" .Values.server.tls.clientCaSecretName -}}
{{- fail "server.tls.clientCaSecretName cannot be null; omit the key to use the chart default (openshell-server-client-ca), or set to \"\" to disable client certificate verification for HTTPS-only mode" -}}
{{- end -}}
{{- end }}
