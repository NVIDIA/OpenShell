# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{{/*
Gateway pod template shared by the StatefulSet and Deployment workload shapes.
*/}}
{{- define "ryno.gatewayPodTemplate" -}}
metadata:
  annotations:
    # Roll the gateway workload when the rendered gateway TOML changes - the
    # gateway only reads /etc/ryno/gateway.toml at startup, so without
    # this annotation a `helm upgrade` that only mutates the ConfigMap would
    # leave pods running with stale config.
    checksum/gateway-config: {{ include (print $.Template.BasePath "/gateway-config.yaml") . | sha256sum }}
    {{- with .Values.podAnnotations }}
    {{- toYaml . | nindent 4 }}
    {{- end }}
  labels:
    {{- include "ryno.labels" . | nindent 4 }}
    {{- with .Values.podLabels }}
    {{- toYaml . | nindent 4 }}
    {{- end }}
spec:
  terminationGracePeriodSeconds: {{ .Values.podLifecycle.terminationGracePeriodSeconds }}
  {{- with .Values.imagePullSecrets }}
  imagePullSecrets:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  serviceAccountName: {{ include "ryno.serviceAccountName" . }}
  {{- if .Values.server.hostGatewayIP }}
  hostAliases:
    - ip: {{ .Values.server.hostGatewayIP | quote }}
      hostnames:
        - host.docker.internal
        - host.ryno.internal
  {{- end }}
  {{- with .Values.podSecurityContext }}
  securityContext:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  containers:
    - name: ryno-gateway
      securityContext:
        {{- toYaml .Values.securityContext | nindent 8 }}
      image: {{ include "ryno.image" . | quote }}
      imagePullPolicy: {{ .Values.gateway.image.pullPolicy | default .Values.global.image.pullPolicy }}
      args:
        - --config
        - /etc/ryno/gateway.toml
        {{- if not .Values.server.externalDbSecret }}
        - --db-url
        - {{ .Values.server.dbUrl | quote }}
        {{- end }}
      env:
        - name: RYNO_REPLICA_ID
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: RYNO_POD_NAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: RYNO_POD_NAMESPACE
          valueFrom:
            fieldRef:
              fieldPath: metadata.namespace
        {{- if eq (include "ryno.workloadKind" .) "deployment" }}
        - name: RYNO_POD_IP
          valueFrom:
            fieldRef:
              fieldPath: status.podIP
        - name: RYNO_PEER_ENDPOINT
          value: {{ printf "%s://$(RYNO_POD_IP):%d" (ternary "http" "https" (default false .Values.server.disableTls)) (int .Values.service.port) | quote }}
        {{- end }}
        - name: RYNO_SERVICE_ACCOUNT_NAME
          value: {{ include "ryno.serviceAccountName" . | quote }}
        - name: RYNO_PEER_SERVICE_NAME
          value: {{ include "ryno.peerServiceName" . | quote }}
        - name: RYNO_PEER_TOKEN_AUDIENCE
          value: "ryno-gateway-peer"
        - name: RYNO_PEER_SERVICE_ACCOUNT_TOKEN_FILE
          value: /var/run/secrets/ryno-peer/token
        - name: RYNO_PEER_POD_LABELS
          value: {{ printf "app.kubernetes.io/name=%s,app.kubernetes.io/instance=%s" (include "ryno.name" .) .Release.Name | quote }}
        {{- if not .Values.server.disableTls }}
        - name: RYNO_PEER_TLS_SERVER_NAME
          value: {{ printf "%s.%s.svc.cluster.local" (include "ryno.fullname" .) .Release.Namespace | quote }}
        {{- if or .Values.pkiInitJob.enabled .Values.certManager.enabled }}
        - name: RYNO_PEER_TLS_CA_FILE
          value: /etc/ryno-tls/server/ca.crt
        {{- end }}
        {{- if eq (include "ryno.gatewayClientCaEnabled" .) "true" }}
        - name: RYNO_PEER_TLS_CERT_FILE
          value: /etc/ryno-tls/peer-client/tls.crt
        - name: RYNO_PEER_TLS_KEY_FILE
          value: /etc/ryno-tls/peer-client/tls.key
        {{- end }}
        {{- end }}
        {{- if not (or .Values.server.credentialDrivers.kubernetesSecrets.enabled .Values.server.credentialDrivers.vault.enabled) }}
        - name: {{ include "ryno.credentialStorageKeyEncryptionKeyEnvName" . }}
          valueFrom:
            secretKeyRef:
              name: {{ include "ryno.credentialStorageKeyEncryptionKeySecretName" . }}
              key: {{ include "ryno.credentialStorageKeyEncryptionKeySecretKey" . }}
        {{- end }}
        {{- if .Values.server.externalDbSecret }}
        - name: RYNO_DB_URL
          valueFrom:
            secretKeyRef:
              name: {{ .Values.server.externalDbSecret }}
              key: uri
        {{- end }}
        # Most gateway settings live in the ConfigMap-backed TOML file
        # mounted at /etc/ryno/gateway.toml. Secret-bearing settings use
        # env vars that the TOML references by name. Some process-level
        # settings consumed by libraries outside gateway code also remain here.
        {{- if and .Values.server.oidc.issuer .Values.server.oidc.caConfigMapName }}
        # OIDC issuer custom-CA: rustls/reqwest read SSL_CERT_FILE for
        # outbound TLS verification. This is a process-level env var
        # consumed by the TLS stack itself, not by gateway code, so it
        # cannot be represented in the gateway TOML schema.
        - name: SSL_CERT_FILE
          value: /etc/ryno-tls/oidc-ca/ca.crt
        {{- end }}
        - name: RYNO_TELEMETRY_ENABLED
          value: {{ .Values.server.telemetryEnabled | quote }}
        {{- if .Values.server.providerTokenGrants.spiffe.enabled }}
        - name: RYNO_GATEWAY_SPIFFE_WORKLOAD_API_SOCKET
          value: {{ .Values.server.providerTokenGrants.spiffe.workloadApiSocketPath | quote }}
        {{- end }}
      volumeMounts:
        {{- if eq (include "ryno.workloadKind" .) "statefulset" }}
        - name: ryno-data
          mountPath: /var/ryno
        {{- end }}
        # ConfigMap directory mounts expose keys through atomic-writer symlinks,
        # while the gateway intentionally rejects symlinked configuration.
        # The checksum annotation above rolls pods when this subPath changes.
        - name: gateway-config
          mountPath: /etc/ryno/gateway.toml
          subPath: gateway.toml
          readOnly: true
        - name: sandbox-jwt
          mountPath: /etc/ryno-jwt
          readOnly: true
        - name: gateway-peer-token
          mountPath: /var/run/secrets/ryno-peer
          readOnly: true
        {{- if not .Values.server.disableTls }}
        - name: tls-cert
          mountPath: /etc/ryno-tls/server
          readOnly: true
        {{- if .Values.certManager.serverIssuerRef.name }}
        - name: tls-external-cert
          mountPath: /etc/ryno-tls/server-external
          readOnly: true
        {{- end }}
        {{- if eq (include "ryno.gatewayClientCaEnabled" .) "true" }}
        - name: peer-client-tls
          mountPath: /etc/ryno-tls/peer-client
          readOnly: true
        - name: tls-client-ca
          mountPath: /etc/ryno-tls/client-ca
          readOnly: true
        {{- end }}
        {{- end }}
        {{- if and .Values.server.oidc.issuer .Values.server.oidc.caConfigMapName }}
        - name: oidc-ca
          mountPath: /etc/ryno-tls/oidc-ca
          readOnly: true
        {{- end }}
        {{- if and .Values.server.credentialDrivers.vault.enabled .Values.server.credentialDrivers.vault.caConfigMapName }}
        - name: vault-ca
          mountPath: /etc/ryno-tls/vault-ca
          readOnly: true
        {{- end }}
        {{- if .Values.upstreamProxy.caBundle.configMapName }}
        - name: upstream-proxy-ca
          mountPath: /etc/ryno-tls/proxy-ca
          readOnly: true
        {{- end }}
        {{- if .Values.server.providerTokenGrants.spiffe.enabled }}
        - name: spiffe-workload-api
          mountPath: {{ dir .Values.server.providerTokenGrants.spiffe.workloadApiSocketPath | quote }}
          readOnly: true
        {{- end }}
        {{- with .Values.server.extraVolumeMounts }}
        {{- toYaml . | nindent 8 }}
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
        name: {{ include "ryno.fullname" . }}-config
    - name: sandbox-jwt
      secret:
        secretName: {{ include "ryno.sandboxJwtSecretName" . }}
        defaultMode: {{ .Values.server.sandboxJwt.secretDefaultMode | default 0400 }}
    - name: gateway-peer-token
      projected:
        defaultMode: 0400
        sources:
          - serviceAccountToken:
              path: token
              audience: ryno-gateway-peer
              expirationSeconds: 3600
    {{- if not .Values.server.disableTls }}
    - name: tls-cert
      secret:
        secretName: {{ .Values.server.tls.certSecretName }}
    {{- if .Values.certManager.serverIssuerRef.name }}
    - name: tls-external-cert
      secret:
        secretName: {{ include "ryno.fullname" . }}-server-external-tls
    {{- end }}
    {{- if eq (include "ryno.gatewayClientCaEnabled" .) "true" }}
    - name: peer-client-tls
      secret:
        secretName: {{ .Values.server.tls.clientTlsSecretName }}
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
    {{- if and .Values.server.credentialDrivers.vault.enabled .Values.server.credentialDrivers.vault.caConfigMapName }}
    - name: vault-ca
      configMap:
        name: {{ .Values.server.credentialDrivers.vault.caConfigMapName }}
        items:
          - key: ca.crt
            path: ca.crt
    {{- end }}
    {{- if .Values.upstreamProxy.caBundle.configMapName }}
    - name: upstream-proxy-ca
      configMap:
        name: {{ .Values.upstreamProxy.caBundle.configMapName | quote }}
        items:
          # The mounted filename stays fixed so the rendered proxy_ca_bundle
          # path does not depend on the operator's ConfigMap key.
          - key: {{ .Values.upstreamProxy.caBundle.key | default "ca.crt" | quote }}
            path: ca.crt
    {{- end }}
    {{- if .Values.server.providerTokenGrants.spiffe.enabled }}
    - name: spiffe-workload-api
      csi:
        driver: csi.spiffe.io
        readOnly: true
    {{- end }}
    {{- with .Values.server.extraVolumes }}
    {{- toYaml . | nindent 4 }}
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
