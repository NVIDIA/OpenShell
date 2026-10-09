# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
{{/*
Render gatewayConfig as TOML.

The chart deliberately treats the top-level keys as TOML table names. Nested
maps are TOML inline tables, and maps in arrays are inline-table array items.
This keeps the YAML-to-TOML boundary generic: adding a non-secret gateway
field must not require a Helm template change.
*/}}

{{/* Render a TOML key. Bare keys keep ordinary output readable. */}}
{{- define "openshell.toml.key" -}}
{{- $key := . | toString -}}
{{- if regexMatch "^[A-Za-z0-9_-]+$" $key -}}
{{- $key -}}
{{- else -}}
{{- $key | quote -}}
{{- end -}}
{{- end -}}

{{/* Render a scalar. Strings are serialized literally. */}}
{{- define "openshell.toml.scalar" -}}
{{- $value := index . 1 -}}
{{- if kindIs "string" $value -}}
{{- if regexMatch "-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----" $value -}}
{{- fail "gatewayConfig must not contain an inline private key; provide it through a Secret-backed file mount" -}}
{{- end -}}
{{- if regexMatch "^[A-Za-z][A-Za-z0-9+.-]*://[^/@[:space:]]*@" $value -}}
{{- fail "gatewayConfig must not contain inline URL credentials; provide them through a Secret-backed environment variable, file, or volume" -}}
{{- end -}}
{{- $value | quote -}}
{{- else if or
    (kindIs "bool" $value)
    (kindIs "int" $value)
    (kindIs "int8" $value)
    (kindIs "int16" $value)
    (kindIs "int32" $value)
    (kindIs "int64" $value)
    (kindIs "uint" $value)
    (kindIs "uint8" $value)
    (kindIs "uint16" $value)
    (kindIs "uint32" $value)
    (kindIs "uint64" $value)
    (kindIs "float32" $value)
    (kindIs "float64" $value) -}}
{{- $value | toJson -}}
{{- else -}}
{{- fail (printf "gatewayConfig values must be strings, booleans, numbers, maps, or arrays; got %s" (kindOf $value)) -}}
{{- end -}}
{{- end -}}

{{/* Render a TOML inline table, omitting YAML null values. */}}
{{- define "openshell.toml.inlineTable" -}}
{{- $root := index . 0 -}}
{{- $table := index . 1 -}}
{{- $entries := list -}}
{{- range $key := keys $table | sortAlpha -}}
{{- $value := get $table $key -}}
{{- if ne $value nil -}}
{{- if eq $key "database_url" -}}
{{- fail "gatewayConfig must not contain database_url; provide database credentials through the chart's Secret-backed OPENSHELL_DB_URL environment variable" -}}
{{- end -}}
{{- $entry := printf "%s = %s" (include "openshell.toml.key" $key) (include "openshell.toml.value" (list $root $value)) -}}
{{- $entries = append $entries $entry -}}
{{- end -}}
{{- end -}}
{{- printf "{ %s }" (join ", " $entries) -}}
{{- end -}}

{{/* Render an array. Maps become TOML inline-table entries. */}}
{{- define "openshell.toml.array" -}}
{{- $root := index . 0 -}}
{{- $array := index . 1 -}}
{{- $entries := list -}}
{{- range $value := $array -}}
{{- if eq $value nil -}}
{{- fail "gatewayConfig arrays cannot contain null values" -}}
{{- end -}}
{{- $entries = append $entries (include "openshell.toml.value" (list $root $value)) -}}
{{- end -}}
{{- printf "[%s]" (join ", " $entries) -}}
{{- end -}}

{{/* Render any supported YAML value as TOML. */}}
{{- define "openshell.toml.value" -}}
{{- $root := index . 0 -}}
{{- $value := index . 1 -}}
{{- if kindIs "map" $value -}}
{{- include "openshell.toml.inlineTable" (list $root $value) -}}
{{- else if kindIs "slice" $value -}}
{{- include "openshell.toml.array" (list $root $value) -}}
{{- else -}}
{{- include "openshell.toml.scalar" (list $root $value) -}}
{{- end -}}
{{- end -}}

{{/* Render the top-level gatewayConfig map as deterministic TOML tables.
Top-level lists represent TOML arrays of tables and preserve their YAML order. */}}
{{- define "openshell.gatewayConfigToml" -}}
{{- $root := . -}}
{{- $config := deepCopy (.Values.gatewayConfig | default dict) -}}
{{- $legacyServer := .Values.server | default dict -}}
{{- $gateway := get $config "openshell.gateway" | default dict -}}
{{- if not (hasKey $gateway "name") -}}{{- $_ := set $gateway "name" (get $legacyServer "name" | default (include "openshell.fullname" .)) -}}{{- end -}}
{{/* The Service and probes own listener ports, so keep runtime listeners aligned. */}}
{{- $_ := set $gateway "bind_address" (printf "0.0.0.0:%v" .Values.service.port) -}}
{{- if .Values.service.healthPort -}}{{- $_ := set $gateway "health_bind_address" (printf "0.0.0.0:%v" .Values.service.healthPort) -}}{{- else -}}{{- $_ := unset $gateway "health_bind_address" -}}{{- end -}}
{{- if .Values.service.metricsPort -}}{{- $_ := set $gateway "metrics_bind_address" (printf "0.0.0.0:%v" .Values.service.metricsPort) -}}{{- else -}}{{- $_ := unset $gateway "metrics_bind_address" -}}{{- end -}}
{{- range $legacyKey, $runtimeKey := dict "logLevel" "log_level" "enableLoopbackServiceHttp" "enable_loopback_service_http" "enableWebsocketTunnel" "enable_websocket_tunnel" "policyValidationFailureMode" "policy_validation_failure_mode" -}}
{{- if not (hasKey $gateway $runtimeKey) -}}{{- $_ := set $gateway $runtimeKey (get $legacyServer $legacyKey) -}}{{- end -}}
{{- end -}}
{{- if not (hasKey $gateway "compute_driver") -}}{{- $_ := set $gateway "compute_driver" "kubernetes" -}}{{- end -}}
{{- $dbMaxConnections := int (get $legacyServer "dbMaxConnections") -}}
{{- if lt $dbMaxConnections 0 -}}
{{- fail "server.dbMaxConnections must not be negative; set 0 to use the gateway default" -}}
{{- end -}}
{{- if and (gt $dbMaxConnections 0) (not (hasKey $gateway "database_max_connections")) -}}
{{- $_ := set $gateway "database_max_connections" $dbMaxConnections -}}
{{- end -}}
{{- $dbLockMaxConnections := int (get $legacyServer "dbLockMaxConnections") -}}
{{- if lt $dbLockMaxConnections 0 -}}
{{- fail "server.dbLockMaxConnections must not be negative; set 0 to use the gateway default" -}}
{{- end -}}
{{- if and (gt $dbLockMaxConnections 0) (not (hasKey $gateway "database_lock_max_connections")) -}}
{{- $_ := set $gateway "database_lock_max_connections" $dbLockMaxConnections -}}
{{- end -}}
{{- $serverDnsNames := .Values.pkiInitJob.serverDnsNames | default list -}}
{{- if .Values.certManager.enabled -}}{{- $serverDnsNames = .Values.certManager.serverDnsNames | default list -}}{{- end -}}
{{- if and $serverDnsNames (not (hasKey $gateway "server_sans")) -}}
{{- $_ := set $gateway "server_sans" (deepCopy $serverDnsNames) -}}
{{- end -}}
{{- $_ := set $config "openshell.gateway" $gateway -}}
{{- $gatewayJwt := get $config "openshell.gateway.gateway_jwt" | default dict -}}
{{- $legacyJwt := get $legacyServer "sandboxJwt" | default dict -}}
{{- range $key, $value := dict "signing_key_path" "/etc/openshell-jwt/signing.pem" "public_key_path" "/etc/openshell-jwt/public.pem" "kid_path" "/etc/openshell-jwt/kid" -}}
{{- if not (hasKey $gatewayJwt $key) -}}{{- $_ := set $gatewayJwt $key $value -}}{{- end -}}
{{- end -}}
{{- if not (hasKey $gatewayJwt "gateway_id") -}}{{- $_ := set $gatewayJwt "gateway_id" (get $legacyJwt "gatewayId" | default (include "openshell.fullname" .)) -}}{{- end -}}
{{- if not (hasKey $gatewayJwt "ttl_secs") -}}{{- $_ := set $gatewayJwt "ttl_secs" (get $legacyJwt "ttlSecs" | default 3600) -}}{{- end -}}
{{- $_ := set $config "openshell.gateway.gateway_jwt" $gatewayJwt -}}
{{- $kubernetesCompat := include "openshell.effectiveKubernetesConfig" . | fromYaml -}}
{{- $_ := set $config "openshell.drivers.kubernetes" $kubernetesCompat -}}
{{- $legacyDrivers := get $legacyServer "drivers" | default dict -}}
{{- $legacyKubernetes := get $legacyDrivers "kubernetes" | default dict -}}
{{- if hasKey $kubernetesCompat "resource_admission" -}}
{{- $_ := set $config "openshell.drivers.kubernetes.resource_admission" (deepCopy (get $kubernetesCompat "resource_admission")) -}}
{{- else -}}
{{- $legacyAdmission := get $legacyKubernetes "resourceAdmission" | default dict -}}
{{- $admission := dict -}}
{{- if hasKey $legacyAdmission "enabled" -}}{{- $_ := set $admission "enabled" (get $legacyAdmission "enabled") -}}{{- end -}}
{{- if and (hasKey $legacyAdmission "requiredLabels") (ne (get $legacyAdmission "requiredLabels") nil) -}}{{- $_ := set $admission "required_labels" (deepCopy (get $legacyAdmission "requiredLabels")) -}}{{- end -}}
{{- $_ := set $config "openshell.drivers.kubernetes.resource_admission" $admission -}}
{{- end -}}
{{- $_ := unset $kubernetesCompat "resource_admission" -}}
{{- $_ := set $config "openshell.drivers.kubernetes" $kubernetesCompat -}}
{{- if not (hasKey $config "openshell.drivers.kubernetes.managed_ssh_ingress") -}}
{{- $_ := set $config "openshell.drivers.kubernetes.managed_ssh_ingress" (dict "enabled" .Values.networkPolicy.enabled "gateway_namespace" .Release.Namespace "gateway_pod_selector" (dict "app.kubernetes.io/name" (include "openshell.name" .) "app.kubernetes.io/instance" .Release.Name)) -}}
{{- end -}}
{{- $legacyOidc := get $legacyServer "oidc" | default dict -}}
{{- $oidcConfig := get $config "openshell.gateway.oidc" | default dict -}}
{{- if or (hasKey $config "openshell.gateway.oidc") (get $legacyOidc "issuer") -}}
{{- if get $legacyOidc "issuer" -}}
{{- if not (hasKey $oidcConfig "issuer") -}}{{- $_ := set $oidcConfig "issuer" (get $legacyOidc "issuer") -}}{{- end -}}
{{- if not (hasKey $oidcConfig "dangerously_allow_insecure_http") -}}{{- $_ := set $oidcConfig "dangerously_allow_insecure_http" (get $legacyOidc "dangerouslyAllowInsecureHttp") -}}{{- end -}}
{{- if not (hasKey $oidcConfig "jwks_allowed_origins") -}}{{- $_ := set $oidcConfig "jwks_allowed_origins" (get $legacyOidc "jwksAllowedOrigins") -}}{{- end -}}
{{- if not (hasKey $oidcConfig "audience") -}}{{- $_ := set $oidcConfig "audience" (get $legacyOidc "audience") -}}{{- end -}}
{{- if not (hasKey $oidcConfig "jwks_ttl_secs") -}}{{- $_ := set $oidcConfig "jwks_ttl_secs" (get $legacyOidc "jwksTtl") -}}{{- end -}}
{{- if and (get $legacyOidc "rolesClaim") (not (hasKey $oidcConfig "roles_claim")) -}}{{- $_ := set $oidcConfig "roles_claim" (get $legacyOidc "rolesClaim") -}}{{- end -}}
{{- if and (get $legacyOidc "adminRole") (not (hasKey $oidcConfig "admin_role")) -}}{{- $_ := set $oidcConfig "admin_role" (get $legacyOidc "adminRole") -}}{{- end -}}
{{- if and (get $legacyOidc "userRole") (not (hasKey $oidcConfig "user_role")) -}}{{- $_ := set $oidcConfig "user_role" (get $legacyOidc "userRole") -}}{{- end -}}
{{- if and (get $legacyOidc "scopesClaim") (not (hasKey $oidcConfig "scopes_claim")) -}}{{- $_ := set $oidcConfig "scopes_claim" (get $legacyOidc "scopesClaim") -}}{{- end -}}
{{- end -}}
{{- $_ := set $config "openshell.gateway.oidc" $oidcConfig -}}
{{- end -}}
{{- $legacyOtlp := get $legacyServer "otlp" | default dict -}}
{{- $otlpConfig := get $config "openshell.gateway.otlp" | default dict -}}
{{- if or (hasKey $config "openshell.gateway.otlp") (get $legacyOtlp "endpoint") -}}
{{- if get $legacyOtlp "endpoint" -}}
{{- if not (hasKey $otlpConfig "endpoint") -}}{{- $_ := set $otlpConfig "endpoint" (get $legacyOtlp "endpoint") -}}{{- end -}}
{{- if not (hasKey $otlpConfig "service_name") -}}{{- $_ := set $otlpConfig "service_name" (get $legacyOtlp "serviceName") -}}{{- end -}}
{{- end -}}
{{- $_ := set $config "openshell.gateway.otlp" $otlpConfig -}}
{{- end -}}
{{- $legacyAuth := get $legacyServer "auth" | default dict -}}
{{- if and (get $legacyAuth "allowUnauthenticatedUsers") (not (hasKey $config "openshell.gateway.auth")) -}}{{- $_ := set $config "openshell.gateway.auth" (dict "allow_unauthenticated_users" true) -}}{{- end -}}
{{- $legacyOcsf := get $legacyServer "ocsfLog" | default dict -}}
{{- $ocsfConfig := get $config "openshell.gateway.ocsf_log" | default dict -}}
{{- if or (hasKey $config "openshell.gateway.ocsf_log") (get $legacyOcsf "enabled") -}}
{{- if get $legacyOcsf "enabled" -}}
{{- if not (hasKey $ocsfConfig "path") -}}{{- $path := get $legacyOcsf "path" -}}{{- if not $path -}}{{- fail "server.ocsfLog.path must be set when server.ocsfLog.enabled is true" -}}{{- end -}}{{- $_ := set $ocsfConfig "path" $path -}}{{- end -}}
{{- if not (hasKey $ocsfConfig "rotation") -}}{{- $rotation := get $legacyOcsf "rotation" | default "daily" -}}{{- if not (has $rotation (list "daily" "never")) -}}{{- fail "server.ocsfLog.rotation must be daily or never" -}}{{- end -}}{{- $_ := set $ocsfConfig "rotation" $rotation -}}{{- end -}}
{{- if not (hasKey $ocsfConfig "queue_capacity") -}}{{- $queueCapacity := 10000 -}}{{- if and (hasKey $legacyOcsf "queueCapacity") (ne (get $legacyOcsf "queueCapacity") nil) -}}{{- $queueCapacity = get $legacyOcsf "queueCapacity" -}}{{- end -}}{{- if lt (int $queueCapacity) 1 -}}{{- fail "server.ocsfLog.queueCapacity and queueMaxBytes must be positive" -}}{{- end -}}{{- $_ := set $ocsfConfig "queue_capacity" (int $queueCapacity) -}}{{- end -}}
{{- if not (hasKey $ocsfConfig "queue_max_bytes") -}}{{- $queueMaxBytes := 16777216 -}}{{- if and (hasKey $legacyOcsf "queueMaxBytes") (ne (get $legacyOcsf "queueMaxBytes") nil) -}}{{- $queueMaxBytes = get $legacyOcsf "queueMaxBytes" -}}{{- end -}}{{- if lt (int $queueMaxBytes) 1 -}}{{- fail "server.ocsfLog.queueCapacity and queueMaxBytes must be positive" -}}{{- end -}}{{- $_ := set $ocsfConfig "queue_max_bytes" (int $queueMaxBytes) -}}{{- end -}}
{{- if not (hasKey $ocsfConfig "schema_version") -}}{{- $schemaVersion := get $legacyOcsf "schemaVersion" | default "" -}}{{- if not (has $schemaVersion (list "" "1.1" "1.3")) -}}{{- fail "server.ocsfLog.schemaVersion must be empty, 1.1, or 1.3" -}}{{- end -}}{{- if $schemaVersion -}}{{- $_ := set $ocsfConfig "schema_version" $schemaVersion -}}{{- end -}}{{- end -}}
{{- if and (eq (get $ocsfConfig "rotation") "daily") (not (hasKey $ocsfConfig "max_files")) -}}{{- $maxFiles := 7 -}}{{- if and (hasKey $legacyOcsf "maxFiles") (ne (get $legacyOcsf "maxFiles") nil) -}}{{- $maxFiles = get $legacyOcsf "maxFiles" -}}{{- end -}}{{- if lt (int $maxFiles) 1 -}}{{- fail "server.ocsfLog.maxFiles must be positive when rotation is daily" -}}{{- end -}}{{- $_ := set $ocsfConfig "max_files" (int $maxFiles) -}}{{- end -}}
{{- end -}}
{{- $_ := set $config "openshell.gateway.ocsf_log" $ocsfConfig -}}
{{- end -}}
{{- $legacyRateLimit := get $legacyServer "grpcRateLimit" | default dict -}}
{{- $rateRequests := int (get $legacyRateLimit "requests" | default 0) -}}
{{- $rateWindow := int (get $legacyRateLimit "windowSeconds" | default 0) -}}
{{- if or (lt $rateRequests 0) (lt $rateWindow 0) -}}{{- fail "server.grpcRateLimit.requests and server.grpcRateLimit.windowSeconds must not be negative; they map to unsigned gateway settings" -}}{{- end -}}
{{- if and (gt $rateRequests 0) (gt $rateWindow 0) -}}
{{- if not (hasKey $gateway "grpc_rate_limit_requests") -}}{{- $_ := set $gateway "grpc_rate_limit_requests" $rateRequests -}}{{- end -}}
{{- if not (hasKey $gateway "grpc_rate_limit_window_seconds") -}}{{- $_ := set $gateway "grpc_rate_limit_window_seconds" $rateWindow -}}{{- end -}}
{{- else if or (gt $rateRequests 0) (gt $rateWindow 0) -}}{{- fail "server.grpcRateLimit requires both requests and windowSeconds to be positive to enable rate limiting, or both 0/unset to disable it" -}}{{- end -}}
{{- $_ := set $config "openshell.gateway" $gateway -}}
{{- $legacyCredentialDrivers := .Values.server.credentialDrivers | default dict -}}
{{- $gatewayForCredentials := get $config "openshell.gateway" | default dict -}}
{{- $rawConfiguredCredentialDrivers := get $gatewayForCredentials "credential_drivers" -}}
{{- $hasConfiguredCredentialDrivers := and (hasKey $gatewayForCredentials "credential_drivers") (ne $rawConfiguredCredentialDrivers nil) -}}
{{- $configuredCredentialDrivers := $rawConfiguredCredentialDrivers | default list -}}
{{- if and $hasConfiguredCredentialDrivers (eq (len $configuredCredentialDrivers) 0) -}}
{{- fail "gatewayConfig.openshell.gateway.credential_drivers must select exactly one backend or be omitted/null to use the chart default" -}}
{{- end -}}
{{- if gt (len $configuredCredentialDrivers) 1 -}}
{{- fail "gatewayConfig.openshell.gateway.credential_drivers may select only one backend" -}}
{{- end -}}
{{- $legacyKubernetesSecrets := get $legacyCredentialDrivers "kubernetesSecrets" | default dict -}}
{{- $legacyVault := get $legacyCredentialDrivers "vault" | default dict -}}
{{- if and $legacyKubernetesSecrets.enabled $legacyVault.enabled -}}
{{- fail "only one external server.credentialDrivers backend can be enabled at a time" -}}
{{- end -}}
{{- if and (not $hasConfiguredCredentialDrivers) (eq (len $configuredCredentialDrivers) 0) -}}
{{- if $legacyKubernetesSecrets.enabled -}}
{{- $_ := set $gatewayForCredentials "credential_drivers" (list "kubernetes-secrets") -}}
{{- else if $legacyVault.enabled -}}
{{- $_ := set $gatewayForCredentials "credential_drivers" (list "vault") -}}
{{- end -}}
{{- end -}}
{{- $_ := set $config "openshell.gateway" $gatewayForCredentials -}}
{{- $effectiveCredentialDrivers := get $gatewayForCredentials "credential_drivers" | default list -}}
{{- if has "kubernetes-secrets" $effectiveCredentialDrivers -}}
{{- $kubernetesSecretsConfig := get $config "openshell.credential_drivers.kubernetes-secrets" | default dict -}}
{{- if not (hasKey $kubernetesSecretsConfig "namespace") -}}
{{- $_ := set $kubernetesSecretsConfig "namespace" (include "openshell.credentialKubernetesSecretsNamespace" .) -}}
{{- end -}}
{{- $_ := set $config "openshell.credential_drivers.kubernetes-secrets" $kubernetesSecretsConfig -}}
{{- end -}}
{{- if and $legacyVault.enabled (has "vault" $effectiveCredentialDrivers) -}}
{{- $vaultConfig := get $config "openshell.credential_drivers.vault" | default dict -}}
{{- range $legacyKey, $runtimeKey := dict "address" "address" "authMethod" "auth_method" "role" "role" -}}
{{- if not (hasKey $vaultConfig $runtimeKey) -}}{{- $_ := set $vaultConfig $runtimeKey (get $legacyVault $legacyKey) -}}{{- end -}}
{{- end -}}
{{- range $legacyKey, $runtimeKey := dict "mount" "mount" "kvVersion" "kv_version" "kubernetesAuthMount" "kubernetes_auth_mount" "serviceAccountTokenPath" "service_account_token_path" "tokenPath" "token_path" "timeoutSecs" "timeout_secs" -}}
{{- if and (get $legacyVault $legacyKey) (not (hasKey $vaultConfig $runtimeKey)) -}}{{- $_ := set $vaultConfig $runtimeKey (get $legacyVault $legacyKey) -}}{{- end -}}
{{- end -}}
{{- $_ := set $config "openshell.credential_drivers.vault" $vaultConfig -}}
{{- end -}}
{{/* External credential drivers own their storage. Do not configure the
chart-managed encrypted database store when any driver is selected: its KEK
environment variable is intentionally not mounted in that mode. */}}
{{- $configuredGateway := get $config "openshell.gateway" | default dict -}}
{{- $configuredCredentialDrivers := get $configuredGateway "credential_drivers" | default list -}}
{{- if gt (len $configuredCredentialDrivers) 0 -}}
{{- $_ := unset $config "openshell.gateway.credential_storage" -}}
{{- else if not (hasKey $config "openshell.gateway.credential_storage") -}}
{{- $_ := set $config "openshell.gateway.credential_storage" (dict "key_encryption_key_env" (include "openshell.credentialStorageKeyEncryptionKeyEnvName" .)) -}}
{{- end -}}
{{/* Kubernetes packaging owns host aliases. Do not permit a second runtime
source to make sandbox callback hostnames disagree with the pod spec. */}}
{{- $kubernetes := get $config "openshell.drivers.kubernetes" | default dict -}}
{{- if .Values.server.hostGatewayIP -}}
{{- $_ := set $kubernetes "host_gateway_ip" .Values.server.hostGatewayIP -}}
{{- else -}}
{{- $_ := unset $kubernetes "host_gateway_ip" -}}
{{- end -}}
{{- $_ := set $config "openshell.drivers.kubernetes" $kubernetes -}}

{{/* A Vault CA is a Kubernetes resource reference, not a free-form runtime
path. Derive its mounted path only from the chart-owned ConfigMap reference. */}}
{{- $credentialDrivers := .Values.credentialDrivers | default dict -}}
{{- $vaultResources := get $credentialDrivers "vault" | default dict -}}
{{- $legacyVaultResources := get $legacyCredentialDrivers "vault" | default dict -}}
{{- $vaultCaConfigMapName := get $vaultResources "caConfigMapName" | default (get $legacyVaultResources "caConfigMapName") -}}
{{- if hasKey $config "openshell.credential_drivers.vault" -}}
{{- $vaultConfig := get $config "openshell.credential_drivers.vault" | default dict -}}
{{- $_ := unset $vaultConfig "ca_bundle" -}}
{{- if and (eq (include "openshell.credentialDriverEnabled" (list . "vault")) "true") $vaultCaConfigMapName -}}
{{- $_ := set $vaultConfig "ca_bundle" "/etc/openshell-tls/vault-ca/ca.crt" -}}
{{- end -}}
{{- $_ := set $config "openshell.credential_drivers.vault" $vaultConfig -}}
{{- end -}}

{{/* TLS resources, mounts, and their corresponding runtime fields have one
owner: server.*. Override any gatewayConfig copies before serializing TOML. */}}
{{- $gateway := get $config "openshell.gateway" | default dict -}}
{{- $_ := set $gateway "disable_tls" .Values.server.disableTls -}}
{{- $_ := set $config "openshell.gateway" $gateway -}}
{{- if .Values.server.disableTls -}}
{{- $_ := unset $config "openshell.gateway.tls" -}}
{{- $_ := unset $kubernetes "client_tls_secret_name" -}}
{{- $_ := set $config "openshell.drivers.kubernetes" $kubernetes -}}
{{- else -}}
{{- if .Values.server.tls.clientTlsSecretName -}}
{{- $_ := set $kubernetes "client_tls_secret_name" .Values.server.tls.clientTlsSecretName -}}
{{- else -}}
{{- $_ := unset $kubernetes "client_tls_secret_name" -}}
{{- end -}}
{{- $_ := set $config "openshell.drivers.kubernetes" $kubernetes -}}
{{- $gatewayTls := get $config "openshell.gateway.tls" | default dict -}}
{{- $_ := set $gatewayTls "cert_path" "/etc/openshell-tls/server/tls.crt" -}}
{{- $_ := set $gatewayTls "key_path" "/etc/openshell-tls/server/tls.key" -}}
{{- if eq (include "openshell.gatewayClientCaEnabled" .) "true" -}}
{{- $_ := set $gatewayTls "client_ca_path" "/etc/openshell-tls/client-ca/ca.crt" -}}
{{- else -}}
{{- $_ := unset $gatewayTls "client_ca_path" -}}
{{- end -}}
{{- if .Values.certManager.serverIssuerRef.name -}}
{{- $_ := set $gatewayTls "external_cert_path" "/etc/openshell-tls/server-external/tls.crt" -}}
{{- $_ := set $gatewayTls "external_key_path" "/etc/openshell-tls/server-external/tls.key" -}}
{{- $_ := set $gatewayTls "external_server_names" (deepCopy (.Values.certManager.serverDnsNames | default list)) -}}
{{- else -}}
{{- $_ := unset $gatewayTls "external_cert_path" -}}
{{- $_ := unset $gatewayTls "external_key_path" -}}
{{- $_ := unset $gatewayTls "external_server_names" -}}
{{- end -}}
{{- $_ := set $config "openshell.gateway.tls" $gatewayTls -}}
{{- end -}}
{{/* A nested YAML map and its dotted top-level table would serialize to
conflicting TOML definitions. Fail before rendering an invalid ConfigMap. */}}
{{- range $tableName := keys $config | sortAlpha -}}
{{- $fields := get $config $tableName -}}
{{- if kindIs "map" $fields -}}
{{- range $fieldName := keys $fields -}}
{{- $nestedTableName := printf "%s.%s" $tableName $fieldName -}}
{{- if hasKey $config $nestedTableName -}}
{{- fail (printf "gatewayConfig defines %q both as a nested map and a dotted top-level table; use only the dotted top-level key" $nestedTableName) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- range $tableName := keys $config | sortAlpha -}}
{{- $fields := get $config $tableName -}}
{{- if ne $fields nil -}}
{{- if and (not (kindIs "map" $fields)) (not (kindIs "slice" $fields)) -}}
{{- fail (printf "gatewayConfig table %q must be a map, got %s" $tableName (kindOf $fields)) -}}
{{- end -}}
{{- $header := list -}}
{{- $segments := splitList "." $tableName -}}
{{- range $index, $segment := $segments -}}
{{- if eq $segment "" -}}
{{- fail (printf "gatewayConfig table %q contains an empty TOML key segment" $tableName) -}}
{{- end -}}
{{- $header = append $header (include "openshell.toml.key" $segment) -}}
{{- end -}}
{{- if kindIs "map" $fields -}}
{{ printf "[%s]\n" (join "." $header) }}
{{- range $fieldName := keys $fields | sortAlpha }}
{{- $value := get $fields $fieldName -}}
{{- if ne $value nil }}
{{- if eq $fieldName "database_url" -}}
{{- fail "gatewayConfig must not contain database_url; provide database credentials through the chart's Secret-backed OPENSHELL_DB_URL environment variable" -}}
{{- end -}}
{{ printf "%s = %s\n" (include "openshell.toml.key" $fieldName) (include "openshell.toml.value" (list $root $value)) }}
{{- end }}
{{- end }}
{{- else -}}
{{- range $index, $entry := $fields -}}
{{- if not (kindIs "map" $entry) -}}
{{- fail (printf "gatewayConfig array-of-tables %q entry %d must be a map, got %s" $tableName $index (kindOf $entry)) -}}
{{- end -}}
{{ printf "[[%s]]\n" (join "." $header) }}
{{- range $fieldName := keys $entry | sortAlpha }}
{{- $value := get $entry $fieldName -}}
{{- if ne $value nil }}
{{- if eq $fieldName "database_url" -}}
{{- fail "gatewayConfig must not contain database_url; provide database credentials through the chart's Secret-backed OPENSHELL_DB_URL environment variable" -}}
{{- end -}}
{{ printf "%s = %s\n" (include "openshell.toml.key" $fieldName) (include "openshell.toml.value" (list $root $value)) }}
{{- end }}
{{- end }}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
