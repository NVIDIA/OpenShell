# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{{/* A missing supervisor autoscaling map means disabled on older releases. */}}
{{- define "openshell.supervisorAutoscalingEnabled" -}}
{{- $a := get (.Values.supervisor | default dict) "autoscaling" | default dict -}}
{{- if and (kindIs "map" $a) (get $a "enabled") -}}true{{- end -}}
{{- end }}

{{- define "openshell.validateSupervisorAutoscaling" -}}
{{- $a := get (.Values.supervisor | default dict) "autoscaling" | default dict -}}
{{- if not (kindIs "map" $a) -}}
{{- fail "supervisor.autoscaling must be a map" -}}
{{- end -}}
{{- if and (hasKey $a "enabled") (not (kindIs "invalid" (get $a "enabled"))) (not (kindIs "bool" (get $a "enabled"))) -}}
{{- fail "supervisor.autoscaling.enabled must be a boolean" -}}
{{- end -}}
{{- if eq (include "openshell.supervisorAutoscalingEnabled" .) "true" -}}
{{- if not (include "openshell.supervisorEnabled" .) -}}
{{- fail "supervisor.autoscaling.enabled requires supervisor_topology = gateway" -}}
{{- end -}}
{{- $min := include "openshell.wholeNumber" (get $a "minReplicas") -}}
{{- $max := include "openshell.wholeNumber" (get $a "maxReplicas") -}}
{{- if or (eq $min "") (lt (int64 $min) 1) -}}
{{- fail "supervisor.autoscaling.minReplicas must be an integer of at least 1; when upgrading older values, use --reset-then-reuse-values or set all supervisor.autoscaling values explicitly" -}}
{{- end -}}
{{- if or (eq $max "") (lt (int64 $max) (int64 $min)) -}}
{{- fail "supervisor.autoscaling.maxReplicas must be an integer greater than or equal to minReplicas" -}}
{{- end -}}
{{- $memory := toString (get $a "targetMemoryAverageValue") -}}
{{- if or (not (regexMatch "^[+]?([0-9]+([.][0-9]*)?|[.][0-9]+)([KMGTPE]i|[numkMGTPE]|[eE][+-]?[0-9]+)?$" $memory)) (not (regexMatch "[1-9]" (regexFind "^[+]?[0-9.]*" $memory))) -}}
{{- fail "supervisor.autoscaling.targetMemoryAverageValue must be a positive Kubernetes memory quantity, such as 512Mi" -}}
{{- end -}}
{{- end -}}
{{- end }}
