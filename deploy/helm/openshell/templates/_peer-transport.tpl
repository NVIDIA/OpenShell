# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{{/*
Gateway peer transport.

A gateway on PostgreSQL expects peer routing: it relays session-bound sandbox
traffic to the replica that owns the sandbox supervisor. Peers share the
gateway listener, so server.disableTls=true also makes peer traffic, including
the peer ServiceAccount bearer token, plaintext. These helpers keep the chart
aligned with the gateway's startup check.
*/}}

{{/*
"true" when the gateway uses PostgreSQL. Mirrors the gateway's store selection
(postgres:// or postgresql:// URL => multi-replica store), which is what makes
the gateway expect peer routing regardless of the replica count.
*/}}
{{- define "openshell.postgresConfigured" -}}
{{- $dbUrl := toString (.Values.server.dbUrl | default "") -}}
{{- if or .Values.server.externalDbSecret (hasPrefix "postgres://" $dbUrl) (hasPrefix "postgresql://" $dbUrl) -}}
true
{{- end -}}
{{- end }}

{{/*
server.peer.allowInsecureTransport as "true" or "". Uses dig so a release
upgraded with --reuse-values, whose stored values predate server.peer, still
renders. Rejects non-boolean values so --set-string "false" cannot opt out.
*/}}
{{- define "openshell.peerAllowInsecureTransportValue" -}}
{{- $allow := dig "peer" "allowInsecureTransport" false (.Values.server | default dict) -}}
{{- if not (kindIs "bool" $allow) -}}
{{- fail (printf "server.peer.allowInsecureTransport must be true or false, got %v" $allow) -}}
{{- end -}}
{{- if $allow -}}
true
{{- end -}}
{{- end }}

{{/*
"true" when the chart renders OPENSHELL_PEER_ALLOW_INSECURE_TRANSPORT: the
operator opted out AND the gateway serves plaintext. The opt-out is ignored on
a TLS gateway, where peers always use https.
*/}}
{{- define "openshell.peerAllowInsecureTransport" -}}
{{- if and .Values.server.disableTls (include "openshell.peerAllowInsecureTransportValue" .) -}}
true
{{- end -}}
{{- end }}

{{/*
Refuse to render plaintext peer transport for PostgreSQL-backed gateways
unless the operator opted out explicitly. Included from the workload templates.
*/}}
{{- define "openshell.validatePeerTransport" -}}
{{- $allowInsecure := include "openshell.peerAllowInsecureTransportValue" . -}}
{{- if and .Values.server.disableTls (include "openshell.postgresConfigured" .) (not $allowInsecure) -}}
{{- fail "server.disableTls=true with PostgreSQL (server.externalDbSecret or a postgres:// server.dbUrl) sends gateway peer traffic and peer ServiceAccount tokens in plaintext. For an existing plaintext release, set server.peer.allowInsecureTransport=true to keep its current behavior on a trusted network; turning gateway TLS on in place strands existing sandboxes. For a new install, keep server.disableTls=false, or behind a Gateway API proxy with an HTTPS listener set grpcRoute.backendTLSPolicy.enabled=true and server.tls.enableMtls=false. See https://docs.nvidia.com/openshell/latest/kubernetes/high-availability#secure-peer-transport" -}}
{{- end -}}
{{- end }}
