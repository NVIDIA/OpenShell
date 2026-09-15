{{/*
Render gatewayConfig as TOML.

The chart deliberately treats the top-level keys as TOML table names. Nested
maps are TOML inline tables, and maps in arrays are inline-table array items.
This keeps the YAML-to-TOML boundary generic: adding a non-secret gateway
field must not require a Helm template change.
*/}}

{{/* Quote a TOML key. Quoted keys safely support every YAML map key. */}}
{{- define "openshell.toml.key" -}}
{{- . | toString | quote -}}
{{- end -}}

{{/* Render a scalar. Strings alone are Helm-templated. */}}
{{- define "openshell.toml.scalar" -}}
{{- $root := index . 0 -}}
{{- $value := index . 1 -}}
{{- if kindIs "string" $value -}}
{{- tpl $value $root | quote -}}
{{- else if or (kindIs "bool" $value) (kindIs "int" $value) (kindIs "int64" $value) (kindIs "float64" $value) -}}
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
{{- $config := .Values.gatewayConfig | default dict -}}
{{- range $tableName := keys $config | sortAlpha -}}
{{- $fields := get $config $tableName -}}
{{- if ne $fields nil -}}
{{- if not (kindIs "map" $fields) -}}
{{- fail (printf "gatewayConfig table %q must be a map, got %s" $tableName (kindOf $fields)) -}}
{{- end -}}
[{{ include "openshell.toml.key" $tableName }}]
{{- range $fieldName := keys $fields | sortAlpha }}
{{- $value := get $fields $fieldName -}}
{{- if ne $value nil }}
{{ include "openshell.toml.key" $fieldName }} = {{ include "openshell.toml.value" (list $root $value) }}
{{- end }}
{{- end }}

{{- end -}}
{{- end -}}
{{- end -}}
