# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{{/*
Whether the chart renders a HorizontalPodAutoscaler for the gateway workload.
A missing autoscaling map (for example `helm upgrade --reuse-values` from a
release that predates these values) means disabled.
*/}}
{{- define "openshell.autoscalingEnabled" -}}
{{- $autoscaling := .Values.gateway.autoscaling | default dict -}}
{{- if and (kindIs "map" $autoscaling) (get $autoscaling "enabled") -}}true{{- end -}}
{{- end }}

{{/*
Largest replica count the chart can run: autoscaling.maxReplicas when the
HPA is enabled, otherwise replicaCount.
*/}}
{{- define "openshell.maxReplicas" -}}
{{- if eq (include "openshell.autoscalingEnabled" .) "true" -}}
{{- int (get .Values.gateway.autoscaling "maxReplicas" | default 1) -}}
{{- else -}}
{{- int (default 1 .Values.gateway.replicaCount) -}}
{{- end -}}
{{- end }}

{{/*
Name of the value that sets the largest replica count, for error messages.
*/}}
{{- define "openshell.maxReplicasSource" -}}
{{- ternary "gateway.autoscaling.maxReplicas" "gateway.replicaCount" (eq (include "openshell.autoscalingEnabled" .) "true") -}}
{{- end }}

{{/*
Validate autoscaling values. Called from openshell.validateValues.
*/}}
{{- define "openshell.validateAutoscaling" -}}
{{- if eq (include "openshell.autoscalingEnabled" .) "true" -}}
{{- $a := .Values.gateway.autoscaling -}}
{{- if not (and (hasKey $a "minReplicas") (hasKey $a "maxReplicas")) -}}
{{- fail "gateway.autoscaling.minReplicas and gateway.autoscaling.maxReplicas are not set. helm upgrade --reuse-values keeps the values of a release that predates the chart's autoscaling defaults; upgrade with --reset-then-reuse-values, or set the autoscaling values explicitly, including gateway.autoscaling.behavior." -}}
{{- end -}}
{{- $min := int (get $a "minReplicas" | default 0) -}}
{{- $max := int (get $a "maxReplicas" | default 0) -}}
{{- if lt $min 1 -}}
{{- fail "gateway.autoscaling.minReplicas must be at least 1." -}}
{{- end -}}
{{- if lt $max $min -}}
{{- fail "gateway.autoscaling.maxReplicas must be greater than or equal to gateway.autoscaling.minReplicas." -}}
{{- end -}}
{{- $cpu := get $a "targetCPUUtilizationPercentage" -}}
{{- $memory := get $a "targetMemoryUtilizationPercentage" -}}
{{- if not (or $cpu $memory (get $a "metrics")) -}}
{{- fail "gateway.autoscaling.enabled requires targetCPUUtilizationPercentage, targetMemoryUtilizationPercentage, or gateway.autoscaling.metrics." -}}
{{- end -}}
{{- if and $cpu (ne (include "openshell.hasPositiveRequest" (dict "resources" .Values.gateway.resources "name" "cpu")) "true") -}}
{{- fail "gateway.autoscaling.targetCPUUtilizationPercentage requires a positive gateway.resources.requests.cpu (or gateway.resources.limits.cpu, which Kubernetes copies into an unset request); Kubernetes computes utilization against the container request." -}}
{{- end -}}
{{- if and $memory (ne (include "openshell.hasPositiveRequest" (dict "resources" .Values.gateway.resources "name" "memory")) "true") -}}
{{- fail "gateway.autoscaling.targetMemoryUtilizationPercentage requires a positive gateway.resources.requests.memory (or gateway.resources.limits.memory, which Kubernetes copies into an unset request); Kubernetes computes utilization against the container request." -}}
{{- end -}}
{{- end -}}
{{- end }}

{{/*
"true" when the container request Kubernetes uses for one resource is positive.
That request is resources.requests.<name> when the key is present, even as
null, which the chart renders and Kubernetes stores as zero. Otherwise it is
resources.limits.<name>, which Kubernetes copies only into an absent request.
Helm cannot parse quantities, so the number before any suffix or exponent must
be unsigned or "+" and contain a nonzero digit: 0, 0m, 0Mi, 0.0 and 0e3 are
zero.
*/}}
{{- define "openshell.hasPositiveRequest" -}}
{{- $resources := .resources | default dict -}}
{{- $requests := $resources.requests | default dict -}}
{{- $limits := $resources.limits | default dict -}}
{{- $value := ternary (get $requests .name) (get $limits .name) (hasKey $requests .name) -}}
{{- if and (not (kindIs "invalid" $value)) (regexMatch "^[+]?[0-9.]*[1-9]" (toString $value)) -}}true{{- end -}}
{{- end }}
