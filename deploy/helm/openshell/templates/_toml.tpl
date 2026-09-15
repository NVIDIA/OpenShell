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
{{- if regexMatch "^[A-Za-z][A-Za-z0-9+.-]*://[^/@[:space:]]+:[^/@[:space:]]+@" $rendered -}}
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
{{- if .Values.server.disableTls -}}
{{- $gateway := get $config "openshell.gateway" | default dict -}}
{{- $_ := set $gateway "disable_tls" true -}}
{{- $_ := set $config "openshell.gateway" $gateway -}}
{{- $_ := unset $config "openshell.gateway.tls" -}}
{{- $kubernetes := get $config "openshell.drivers.kubernetes" | default dict -}}
{{- $_ := unset $kubernetes "client_tls_secret_name" -}}
{{- $_ := set $config "openshell.drivers.kubernetes" $kubernetes -}}
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
