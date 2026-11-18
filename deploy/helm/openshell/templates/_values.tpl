{{/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
SPDX-License-Identifier: Apache-2.0 */}}
{{/* Internal compatibility boundary. No template may read values before resolution. */}}

{{/* Merge explicit overrides without Sprig's truthiness fallback. Empty maps clear. */}}
{{- define "openshell.values.overlay" -}}
{{- $dst := index . 0 -}}
{{- range $key, $value := index . 1 -}}
  {{- if eq $value nil -}}
    {{- $_ := unset $dst $key -}}
  {{- else if and (kindIs "map" $value) (gt (len $value) 0) (kindIs "map" (get $dst $key)) -}}
    {{- include "openshell.values.overlay" (list (get $dst $key) $value) -}}
  {{- else -}}
    {{- $_ := set $dst $key (deepCopy $value) -}}
  {{- end -}}
{{- end -}}
{{- end -}}

{{- define "openshell.values.read" -}}
{{- $value := index . 0 -}}
{{- $found := true -}}
{{- range splitList "." (index . 1) -}}
  {{- if and (kindIs "map" $value) (hasKey $value .) -}}
    {{- $value = get $value . -}}
  {{- else -}}
    {{- $found = false -}}
    {{- $value = dict -}}
  {{- end -}}
{{- end -}}
{{- dict "found" (and $found (ne $value nil)) "value" $value | toJson -}}
{{- end -}}

{{- define "openshell.values.write" -}}
{{- $dst := index . 0 -}}
{{- $parts := splitList "." (index . 1) -}}
{{- range initial $parts -}}
  {{- if not (kindIs "map" (get $dst .)) -}}{{- $_ := set $dst . dict -}}{{- end -}}
  {{- $dst = get $dst . -}}
{{- end -}}
{{- $_ := set $dst (last $parts) (index . 2) -}}
{{- end -}}

{{- define "openshell.resolveValues" -}}
{{- if not (hasKey . "_openshellResolved") -}}
{{- $_ := set . "_openshellResolved" true -}}
{{- $raw := deepCopy .Values -}}
{{- $effective := .Files.Get "files/compatibility-defaults.yaml" | fromYaml -}}
{{- include "openshell.values.overlay" (list $effective $raw) -}}
{{- $aliases := .Files.Get "files/value-aliases.yaml" | fromYaml -}}
{{- $runtimeAliases := .Files.Get "files/runtime-aliases.yaml" | fromYaml -}}
{{- $warnings := list -}}
{{- range $legacy := keys $aliases | sortAlpha -}}
  {{- $canonical := get $aliases $legacy -}}
  {{- $old := include "openshell.values.read" (list $raw $legacy) | fromJson -}}
  {{- if $old.found -}}
    {{- $warnings = append $warnings (printf "%s -> %s" $legacy $canonical) -}}
  {{- end -}}
  {{- $resolved := include "openshell.values.read" (list $effective $legacy) | fromJson -}}
  {{- $new := include "openshell.values.read" (list $raw $canonical) | fromJson -}}
  {{- if $new.found -}}
    {{- if and (kindIs "map" $new.value) (gt (len $new.value) 0) (kindIs "map" $resolved.value) -}}
      {{- include "openshell.values.overlay" (list $resolved.value $new.value) -}}
    {{- else -}}
      {{- $_ := set $resolved "value" $new.value -}}
    {{- end -}}
  {{- end -}}
  {{- include "openshell.values.write" (list $effective $canonical $resolved.value) -}}
  {{/* Legacy runtime adapters see the same resolved resource inputs. */}}
  {{- include "openshell.values.write" (list $effective $legacy $resolved.value) -}}
{{- end -}}
{{- if hasKey $raw "server" -}}
  {{- range $legacy, $target := $runtimeAliases -}}
    {{- $old := include "openshell.values.read" (list $raw $legacy) | fromJson -}}
    {{- if $old.found -}}
      {{- $warnings = append $warnings (printf "%s -> gatewayConfig[%q].%s" $legacy $target.table $target.field) -}}
    {{- end -}}
  {{- end -}}
  {{- $warnings = append $warnings "server -> component deployment values or gatewayConfig; see the migration reference for backend selection and OCSF enablement" -}}
{{- end -}}
{{- if and (gt (len $warnings) 0) (semverCompare ">=0.2.0-0" .Chart.Version) -}}
  {{- fail (printf "Deprecated Helm values were removed in chart 0.2.0: %s. Migrate stored values with helm get values, then upgrade --reset-values -f migrated-values.yaml." (join "; " $warnings)) -}}
{{- end -}}
{{- $_ := set . "_openshellValueWarnings" $warnings -}}
{{/* Keep legacy runtime adapters aligned with explicitly configured schema-v2 values. */}}
{{- range $legacy, $target := $runtimeAliases -}}
  {{- $table := get ($effective.gatewayConfig | default dict) $target.table | default dict -}}
  {{- if and (hasKey $table $target.field) (ne (get $table $target.field) nil) -}}
    {{- include "openshell.values.write" (list $effective $legacy (get $table $target.field)) -}}
  {{- end -}}
{{- end -}}
{{- $_ := set . "Values" $effective -}}
{{- if eq (dig "serviceAccount" "automountServiceAccountToken" false .Values.sandbox) true -}}
  {{- fail "sandbox.serviceAccount.automountServiceAccountToken must remain false: sandbox workloads use a scoped projected bootstrap token" -}}
{{- end -}}
{{- end -}}
{{- end -}}
