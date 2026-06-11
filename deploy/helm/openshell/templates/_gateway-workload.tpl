# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{{/*
Gateway pod template shared by the StatefulSet and Deployment workload shapes.
*/}}
{{- define "openshell.gatewayPodTemplate" -}}
metadata:
  annotations:
    # Roll the gateway workload when the rendered gateway TOML changes - the
    # gateway only reads /etc/openshell/gateway.toml at startup, so without
    # this annotation a `helm upgrade` that only mutates the ConfigMap would
    # leave pods running with stale config.
    checksum/gateway-config: {{ include (print $.Template.BasePath "/gateway-config.yaml") . | sha256sum }}
    {{- with .Values.podAnnotations }}
    {{- toYaml . | nindent 4 }}
    {{- end }}
  labels:
    {{- include "openshell.labels" . | nindent 4 }}
    {{- with .Values.podLabels }}
    {{- toYaml . | nindent 4 }}
    {{- end }}
spec:
  terminationGracePeriodSeconds: {{ .Values.podLifecycle.terminationGracePeriodSeconds }}
  {{- with .Values.imagePullSecrets }}
  imagePullSecrets:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  serviceAccountName: {{ include "openshell.serviceAccountName" . }}
  {{- if .Values.server.hostGatewayIP }}
  hostAliases:
    - ip: {{ .Values.server.hostGatewayIP | quote }}
      hostnames:
        - host.docker.internal
        - host.openshell.internal
  {{- end }}
  securityContext:
    {{- toYaml .Values.podSecurityContext | nindent 4 }}
  containers:
    - name: openshell-gateway
      securityContext:
        {{- toYaml .Values.securityContext | nindent 8 }}
      image: {{ include "openshell.image" . | quote }}
      imagePullPolicy: {{ .Values.image.pullPolicy }}
      args:
        - --config
        - /etc/openshell/gateway.toml
        {{- if not .Values.server.externalDbSecret }}
        - --db-url
        - {{ .Values.server.dbUrl | quote }}
        {{- end }}
      env:
        - name: OPENSHELL_REPLICA_ID
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: OPENSHELL_POD_NAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: OPENSHELL_POD_NAMESPACE
          valueFrom:
            fieldRef:
              fieldPath: metadata.namespace
        {{- if eq (include "openshell.workloadKind" .) "deployment" }}
        - name: OPENSHELL_POD_IP
          valueFrom:
            fieldRef:
              fieldPath: status.podIP
        - name: OPENSHELL_PEER_ENDPOINT
          value: {{ printf "%s://$(OPENSHELL_POD_IP):%d" (ternary "http" "https" (default false .Values.server.disableTls)) (int .Values.service.port) | quote }}
        {{- end }}
        - name: OPENSHELL_SERVICE_ACCOUNT_NAME
          value: {{ include "openshell.serviceAccountName" . | quote }}
        - name: OPENSHELL_PEER_SERVICE_NAME
          value: {{ include "openshell.peerServiceName" . | quote }}
        - name: OPENSHELL_PEER_TOKEN_AUDIENCE
          value: "openshell-gateway-peer"
        - name: OPENSHELL_PEER_SERVICE_ACCOUNT_TOKEN_FILE
          value: /var/run/secrets/openshell-peer/token
        - name: OPENSHELL_PEER_POD_LABELS
          value: {{ printf "app.kubernetes.io/name=%s,app.kubernetes.io/instance=%s" (include "openshell.name" .) .Release.Name | quote }}
        {{- if .Values.server.externalDbSecret }}
        - name: OPENSHELL_DB_URL
          valueFrom:
            secretKeyRef:
              name: {{ .Values.server.externalDbSecret }}
              key: uri
        {{- end }}
        # All gateway settings live in the ConfigMap-backed TOML file
        # mounted at /etc/openshell/gateway.toml. The only env var below
        # is a process-level setting consumed by libraries outside
        # gateway code (currently just SSL_CERT_FILE for OIDC issuer TLS).
        {{- if and .Values.server.oidc.issuer .Values.server.oidc.caConfigMapName }}
        # OIDC issuer custom-CA: rustls/reqwest read SSL_CERT_FILE for
        # outbound TLS verification. This is a process-level env var
        # consumed by the TLS stack itself, not by gateway code, so it
        # cannot be represented in the gateway TOML schema.
        - name: SSL_CERT_FILE
          value: /etc/openshell-tls/oidc-ca/ca.crt
        {{- end }}
      volumeMounts:
        {{- if eq (include "openshell.workloadKind" .) "statefulset" }}
        - name: openshell-data
          mountPath: /var/openshell
        {{- end }}
        - name: gateway-config
          mountPath: /etc/openshell
          readOnly: true
        - name: sandbox-jwt
          mountPath: /etc/openshell-jwt
          readOnly: true
        - name: gateway-peer-token
          mountPath: /var/run/secrets/openshell-peer
          readOnly: true
        {{- if not .Values.server.disableTls }}
        - name: tls-cert
          mountPath: /etc/openshell-tls/server
          readOnly: true
        {{- if or .Values.server.tls.clientCaSecretName (and .Values.pkiInitJob.enabled (not .Values.certManager.enabled)) (and .Values.certManager.enabled .Values.certManager.clientCaFromServerTlsSecret) }}
        - name: tls-client-ca
          mountPath: /etc/openshell-tls/client-ca
          readOnly: true
        {{- end }}
        {{- end }}
        {{- if and .Values.server.oidc.issuer .Values.server.oidc.caConfigMapName }}
        - name: oidc-ca
          mountPath: /etc/openshell-tls/oidc-ca
          readOnly: true
        {{- end }}
      ports:
        - name: grpc
          containerPort: {{ .Values.service.port }}
          protocol: TCP
        - name: health
          containerPort: {{ .Values.service.healthPort }}
          protocol: TCP
        {{- if .Values.service.metricsPort }}
        - name: metrics
          containerPort: {{ .Values.service.metricsPort }}
          protocol: TCP
        {{- end }}
      startupProbe:
        httpGet:
          path: /healthz
          port: health
        periodSeconds: {{ .Values.probes.startup.periodSeconds }}
        timeoutSeconds: {{ .Values.probes.startup.timeoutSeconds }}
        failureThreshold: {{ .Values.probes.startup.failureThreshold }}
      livenessProbe:
        httpGet:
          path: /healthz
          port: health
        initialDelaySeconds: {{ .Values.probes.liveness.initialDelaySeconds }}
        periodSeconds: {{ .Values.probes.liveness.periodSeconds }}
        timeoutSeconds: {{ .Values.probes.liveness.timeoutSeconds }}
        failureThreshold: {{ .Values.probes.liveness.failureThreshold }}
      readinessProbe:
        httpGet:
          path: /readyz
          port: health
        initialDelaySeconds: {{ .Values.probes.readiness.initialDelaySeconds }}
        periodSeconds: {{ .Values.probes.readiness.periodSeconds }}
        timeoutSeconds: {{ .Values.probes.readiness.timeoutSeconds }}
        failureThreshold: {{ .Values.probes.readiness.failureThreshold }}
      resources:
        {{- toYaml .Values.resources | nindent 8 }}
  volumes:
    - name: gateway-config
      configMap:
        name: {{ include "openshell.fullname" . }}-config
    - name: sandbox-jwt
      secret:
        secretName: {{ include "openshell.sandboxJwtSecretName" . }}
        defaultMode: {{ .Values.server.sandboxJwt.secretDefaultMode | default 0400 }}
    - name: gateway-peer-token
      projected:
        defaultMode: 0400
        sources:
          - serviceAccountToken:
              path: token
              audience: openshell-gateway-peer
              expirationSeconds: 3600
    {{- if not .Values.server.disableTls }}
    - name: tls-cert
      secret:
        secretName: {{ .Values.server.tls.certSecretName }}
    {{- if or .Values.server.tls.clientCaSecretName (and .Values.pkiInitJob.enabled (not .Values.certManager.enabled)) (and .Values.certManager.enabled .Values.certManager.clientCaFromServerTlsSecret) }}
    - name: tls-client-ca
      secret:
        {{- if or (and .Values.pkiInitJob.enabled (not .Values.certManager.enabled)) (and .Values.certManager.enabled .Values.certManager.clientCaFromServerTlsSecret) }}
        secretName: {{ .Values.server.tls.certSecretName }}
        items:
          - key: ca.crt
            path: ca.crt
        {{- else }}
        secretName: {{ .Values.server.tls.clientCaSecretName }}
        {{- end }}
    {{- end }}
    {{- end }}
    {{- if and .Values.server.oidc.issuer .Values.server.oidc.caConfigMapName }}
    - name: oidc-ca
      configMap:
        name: {{ .Values.server.oidc.caConfigMapName }}
    {{- end }}
  {{- with .Values.nodeSelector }}
  nodeSelector:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- with .Values.affinity }}
  affinity:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- with .Values.tolerations }}
  tolerations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
{{- end }}
