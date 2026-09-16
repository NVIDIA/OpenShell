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

{{/* Render a scalar. Strings alone are Helm-templated. */}}
{{- define "openshell.toml.scalar" -}}
{{- $root := index . 0 -}}
{{- $value := index . 1 -}}
{{- if kindIs "string" $value -}}
{{- $rendered := tpl $value $root -}}
{{- if regexMatch "-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----" $rendered -}}
{{- fail "gatewayConfig must not contain an inline private key; provide it through a Secret-backed file mount" -}}
{{- end -}}
{{- if regexMatch "^[A-Za-z][A-Za-z0-9+.-]*://[^/@[:space:]]*@" $rendered -}}
{{- fail "gatewayConfig must not contain inline URL credentials; provide them through a Secret-backed environment variable, file, or volume" -}}
{{- end -}}
{{- $rendered | quote -}}
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

{{/* Render the top-level gatewayConfig map as deterministic TOML tables. */}}
{{- define "openshell.gatewayConfigToml" -}}
{{- $root := . -}}
{{- $config := deepCopy (.Values.gatewayConfig | default dict) -}}
{{/* Kubernetes packaging owns host aliases. Do not permit a second runtime
source to make sandbox callback hostnames disagree with the pod spec. */}}
{{- $kubernetes := get $config "openshell.drivers.kubernetes" | default dict -}}
{{- if .Values.server.hostGatewayIP -}}
{{- $_ := set $kubernetes "host_gateway_ip" .Values.server.hostGatewayIP -}}
{{- else -}}
{{- $_ := unset $kubernetes "host_gateway_ip" -}}
{{- end -}}
{{- $_ := set $config "openshell.drivers.kubernetes" $kubernetes -}}

{{/* RFC 0012 packaging inputs are authoritative for paired runtime images,
the network-fence acknowledgement, and corporate proxy Secret wiring. */}}
{{- $runtime := .Values.sandboxRuntime | default dict -}}
{{- $runtimeImage := get $runtime "image" | default dict -}}
{{- $supervisor := .Values.supervisor | default dict -}}
{{- $supervisorImage := get $supervisor "image" | default dict -}}
{{- $runtimeTag := get $runtimeImage "tag" | default .Values.image.tag | default .Chart.AppVersion -}}
{{- $supervisorTag := get $supervisorImage "tag" | default .Values.image.tag | default .Chart.AppVersion -}}
{{- $_ := set $kubernetes "sandbox_runtime_image" (printf "%s:%s" (get $runtimeImage "repository" | default "ghcr.io/nvidia/openshell/sandbox") $runtimeTag) -}}
{{- $_ := set $kubernetes "supervisor_image" (printf "%s:%s" (get $supervisorImage "repository" | default "ghcr.io/nvidia/openshell/supervisor") $supervisorTag) -}}
{{- if get $runtimeImage "pullPolicy" -}}
{{- $_ := set $kubernetes "sandbox_runtime_image_pull_policy" (include "openshell.canonicalImagePullPolicy" (get $runtimeImage "pullPolicy")) -}}
{{- else -}}{{- $_ := unset $kubernetes "sandbox_runtime_image_pull_policy" -}}{{- end -}}
{{- if get $supervisorImage "pullPolicy" -}}
{{- $_ := set $kubernetes "supervisor_image_pull_policy" (include "openshell.canonicalImagePullPolicy" (get $supervisorImage "pullPolicy")) -}}
{{- else -}}{{- $_ := unset $kubernetes "supervisor_image_pull_policy" -}}{{- end -}}
{{- $runtimeConfig := get $supervisor "sandboxRuntime" | default dict -}}
{{- $_ := set $kubernetes "sandbox_runtime" (dict "network_policy_enforced" (get $runtimeConfig "networkPolicyEnforced") "boundary_port" (get $runtimeConfig "boundaryPort" | default 5500)) -}}
{{- $proxy := .Values.upstreamProxy | default dict -}}
{{- range $runtimeKey := list "https_proxy" "no_proxy" "proxy_auth_secret_name" "proxy_auth_secret_key" "proxy_auth_allow_insecure" "proxy_connect_by_hostname" -}}{{- $_ := unset $kubernetes $runtimeKey -}}{{- end -}}
{{- if get $proxy "url" -}}{{- $_ := set $kubernetes "https_proxy" (get $proxy "url") -}}{{- end -}}
{{- if get $proxy "noProxy" -}}{{- $_ := set $kubernetes "no_proxy" (get $proxy "noProxy") -}}{{- end -}}
{{- $proxySecret := get $proxy "authSecret" | default dict -}}
{{- if get $proxySecret "name" -}}{{- $_ := set $kubernetes "proxy_auth_secret_name" (get $proxySecret "name") -}}{{- end -}}
{{- if get $proxySecret "key" -}}{{- $_ := set $kubernetes "proxy_auth_secret_key" (get $proxySecret "key") -}}{{- end -}}
{{- if or (get $proxySecret "name") (get $proxySecret "key") -}}{{- $_ := set $kubernetes "proxy_auth_allow_insecure" (get $proxy "authAllowInsecure") -}}{{- end -}}
{{- if get $proxy "connectByHostname" -}}{{- $_ := set $kubernetes "proxy_connect_by_hostname" true -}}{{- end -}}
{{- $_ := set $config "openshell.drivers.kubernetes" $kubernetes -}}

{{/* A Vault CA is a Kubernetes resource reference, not a free-form runtime
path. Derive its mounted path only from the chart-owned ConfigMap reference. */}}
{{- $credentialDrivers := .Values.credentialDrivers | default dict -}}
{{- $vaultResources := get $credentialDrivers "vault" | default dict -}}
{{- if hasKey $config "openshell.credential_drivers.vault" -}}
{{- $vaultConfig := get $config "openshell.credential_drivers.vault" | default dict -}}
{{- $_ := unset $vaultConfig "ca_bundle" -}}
{{- if and (eq (include "openshell.credentialDriverEnabled" (list . "vault")) "true") (get $vaultResources "caConfigMapName") -}}
{{- $_ := set $vaultConfig "ca_bundle" "/etc/openshell-tls/vault/ca.crt" -}}
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
{{- range $tableName := keys $config | sortAlpha -}}
{{- $fields := get $config $tableName -}}
{{- if ne $fields nil -}}
{{- if not (kindIs "map" $fields) -}}
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
{{- end -}}
{{- end -}}
{{- end -}}
