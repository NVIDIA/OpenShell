# Kubernetes TLS and multi-replica gateways

Checks for gateway replicas, peer relay, certificates, SPIFFE token grants, and backend TLS on Kubernetes and OpenShift. Start with [kubernetes.md](kubernetes.md) for the Helm release, gateway workload, and sandbox pods.

## Multi-replica gateways

For multi-replica gateway installs, supervisor and client session traffic may
be served by a non-owner gateway replica and relayed to the current supervisor
owner over the internal `PeerRelay` RPC. Check the headless peer Service,
projected peer ServiceAccount token volume, and TokenReview RBAC:

```bash
kubectl -n openshell get svc openshell-peer -o wide
kubectl -n openshell get endpoints openshell-peer
kubectl -n openshell get pod -l app.kubernetes.io/instance=openshell \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{.spec.volumes[?(@.name=="gateway-peer-token")]}{"\n"}{.spec.volumes[?(@.name=="peer-client-tls")]}{"\n"}{.spec.containers[0].env[?(@.name=="OPENSHELL_PEER_SERVICE_ACCOUNT_TOKEN_FILE")]}{"\n"}{.spec.containers[0].env[?(@.name=="OPENSHELL_PEER_ENDPOINT")]}{"\n"}{.spec.containers[0].env[?(@.name=="OPENSHELL_PEER_TLS_SERVER_NAME")]}{"\n"}{end}'
kubectl auth can-i create tokenreviews.authentication.k8s.io \
  --as=system:serviceaccount:openshell:openshell
kubectl auth can-i get pods -n openshell \
  --as=system:serviceaccount:openshell:openshell
GATEWAY_DEPLOYMENT="$(kubectl -n openshell get deployment openshell >/dev/null 2>&1 && echo deployment/openshell || echo statefulset/openshell)"
kubectl -n openshell logs "${GATEWAY_DEPLOYMENT}" --tail=200 | grep -E 'gateway peer|PeerRelay|supervisor owner|owner relay'
```

Expected gateway startup logs include
`gateway peer ServiceAccount TokenReview authentication enabled`. If peer relay
calls fail with `Unauthenticated`, verify the `gateway-peer-token` projected
volume has audience `openshell-gateway-peer` and that the receiving gateway can
create TokenReviews. If they fail with `PermissionDenied`, verify the gateway
ServiceAccount name, release namespace, pod UID, and Helm selector labels match
the live gateway pods. Deployment-backed gateway pods should also publish
`OPENSHELL_PEER_ENDPOINT` from their pod IP. The
`OPENSHELL_PEER_SERVICE_ACCOUNT_TOKEN_FILE` name follows the existing
token-file convention used by `OPENSHELL_SANDBOX_TOKEN_FILE` and
`OPENSHELL_K8S_SA_TOKEN_FILE`.

For TLS-enabled gateways, peer clients verify the stable gateway Service DNS
name and load the chart CA plus client identity from
`OPENSHELL_PEER_TLS_CA_FILE`, `OPENSHELL_PEER_TLS_CERT_FILE`, and
`OPENSHELL_PEER_TLS_KEY_FILE`. If peer calls fail during TLS negotiation, verify
the `peer-client-tls` volume exists, those files are readable, and the server
certificate includes the name in `OPENSHELL_PEER_TLS_SERVER_NAME`.

To check per-replica capacity on a multi-replica gateway, read each gateway
pod's metrics and the autoscaler:

```bash
for pod in $(kubectl -n openshell get pod \
    -l app.kubernetes.io/name=openshell,app.kubernetes.io/instance=openshell \
    -o jsonpath='{range .items[?(@.spec.containers[0].name=="openshell-gateway")]}{.metadata.name}{" "}{end}'); do
  echo "${pod}"
  kubectl get --raw "/api/v1/namespaces/openshell/pods/${pod}:9090/proxy/metrics" \
    | grep -E '^openshell_server_(supervisor_sessions|relay_pending|relay_rejected_total|routed_request_attempts_total)'
done
kubectl -n openshell get hpa
kubectl -n openshell describe hpa openshell
```

The JSONPath filter keeps only pods whose first container is the gateway
(`openshell-gateway`). It skips certificate hook Job pods, which older charts
labeled like gateway pods. The metrics port is `service.metricsPort` (default
`9090`).

The API server proxy connects to each pod from the control plane. A
NetworkPolicy that accepts the metrics port only from a monitoring namespace
blocks it unless the policy also allows the control plane. In that case,
read one pod at a time through `kubectl port-forward`, which reaches the pod
through the kubelet and is not blocked by NetworkPolicy:

```bash
kubectl -n openshell port-forward pod/<gateway-pod> 9090:9090 >/dev/null &
pf_pid=$!
sleep 2
curl -s http://localhost:9090/metrics \
  | grep -E '^openshell_server_(supervisor_sessions|relay_pending|relay_rejected_total|routed_request_attempts_total)'
kill "${pf_pid}"
```

## TLS and certificates

Check required Helm deployment secrets:

```bash
kubectl -n openshell get secret \
  openshell-server-tls \
  openshell-server-client-ca \
  openshell-client-tls \
  openshell-jwt-keys
```

When `server.tls.clientCaSecretName=""`, the chart intentionally omits
`client_ca_path` and the `tls-client-ca` mount, even with built-in PKI or
cert-manager. That is expected; do not treat a missing `tls-client-ca` pod
mount as a defect (`openshell-server-client-ca` may still exist from PKI).
User auth is OIDC or trusted proxy (`server.auth.allowUnauthenticatedUsers=true`);
supervisor transport still uses `openshell-client-tls`.

In cert-manager installs, `certManager.enabled=true` makes cert-manager own TLS
generation. The Helm chart should still render the `openshell-certgen`
pre-install/pre-upgrade hook in JWT-only mode to create `openshell-jwt-keys`,
even if `pkiInitJob.enabled` remains true.
If the gateway pod is pending with `MountVolume.SetUp failed for volume
"sandbox-jwt"` and `openshell-jwt-keys` is absent, inspect the rendered
`templates/certgen.yaml` output and the hook Job logs; cert-manager creates TLS
Secrets but does not create the sandbox JWT signing Secret.

If the gateway exits with `failed to read sandbox JWT signing key from
/etc/openshell-jwt/signing.pem`, verify that `openshell-jwt-keys` contains
`signing.pem`, `public.pem`, and `kid`, and that the gateway workload mounts the
`sandbox-jwt` secret at `/etc/openshell-jwt`. The sandbox JWT mount is required
even when local Helm values disable TLS.

If `certManager.serverIssuerRef` points the server certificate at an external
Issuer or ClusterIssuer (for example an ACME issuer, for a publicly-trusted
cert on an OpenShift `Route` with TLS passthrough — see
`openshiftRoute.enabled`), the chart creates **two** server certificates: an
internal one (chart CA, internal SANs) and an external one (from the configured
issuer, external SANs only).  The gateway uses SNI to present the right cert.

Check the external `Certificate`/`CertificateRequest`/`Challenge` resources
directly when the external secret never becomes Ready:

```bash
kubectl -n openshell get certificate,certificaterequest,challenge
kubectl -n openshell describe certificate openshell-server-external
oc -n openshell get route
```

ACME issuers reject certificate requests that include internal-only names
(`*.svc.cluster.local`, `localhost`, loopback IPs) and require the
`commonName` to also be a SAN — the external `Certificate` only requests the
hostnames in `certManager.serverDnsNames`, for exactly this reason.

If sandbox supervisors fail their TLS handshake to the gateway with
`UnknownCA` after configuring `serverIssuerRef`, the most likely cause is
`server.grpcEndpoint` set to the external hostname.  This forces supervisors
to connect via the external hostname, receiving the ACME cert (via SNI) which
they cannot verify against the chart CA.  Remove `server.grpcEndpoint` or set
it to the internal service name so supervisors receive the internal cert:

```bash
helm -n openshell get values openshell | grep -E 'grpcEndpoint|clientCaFromServerTlsSecret|clientCaSecretName|serverIssuerRef|caSecretName'
# server.grpcEndpoint should be unset or point to internal service name
```

Less commonly, `UnknownCA` can occur if the gateway's client-verification CA
is misconfigured.  The default `clientCaFromServerTlsSecret=true` is correct
for all configurations — the internal server certificate is always signed by
the chart CA (the same CA that signs the client cert), so its `ca.crt` is
the right trust anchor. Supervisor Pods project only `ca.crt` from the copied
Secret; `tls.crt` and `tls.key` are reserved for user clients and must not be
visible in a sandbox. Only override this if you intentionally mount a
separate client CA via `server.tls.clientCaSecretName`.  Verify the mounted
client CA matches the CA that signed the client certificate:

```bash
kubectl -n openshell get statefulset openshell -o jsonpath='{.spec.template.spec.volumes[?(@.name=="tls-client-ca")]}' | jq .
# Should show items filter for ca.crt from openshell-server-tls
```

If `gatewayConfig.openshell.drivers.kubernetes.provider_spiffe_workload_api_socket_path`
is set, the gateway should still render `[openshell.gateway.gateway_jwt]` and
mount the `sandbox-jwt` Secret.
SPIRE is used by both the gateway and sandbox supervisors for dynamic provider
token grants. The gateway pod must mount the `spiffe-workload-api` CSI volume
and set `OPENSHELL_GATEWAY_SPIFFE_WORKLOAD_API_SOCKET`; supervisor Pods must
receive the matching Workload API socket from the Kubernetes driver config.
The gateway verifies supervisor JWT-SVIDs from JWT bundles fetched through this
Workload API socket, not from the SPIRE OIDC discovery endpoint.
Verify that SPIRE is installed, the CSI driver is available, and the Kubernetes
driver config includes `provider_spiffe_workload_api_socket_path`:

```bash
helm -n openshell get values openshell | grep provider_spiffe_workload_api_socket_path
kubectl get pods -A | grep -E 'spire|spiffe'
kubectl -n openshell get configmap openshell-config -o yaml | grep provider_spiffe_workload_api_socket_path
kubectl -n openshell get pod -l app.kubernetes.io/name=helm-chart -o jsonpath="{.items[*].spec.containers[*].env[?(@.name==\"OPENSHELL_GATEWAY_SPIFFE_WORKLOAD_API_SOCKET\")].value}{\"\n\"}"
```

Sandbox pods using provider token grants should have an
`openshell.ai/sandbox-id` annotation, an `openshell.ai/managed-by=openshell`
label, supervisor env vars `OPENSHELL_K8S_SA_TOKEN_FILE` and
`OPENSHELL_PROVIDER_SPIFFE_WORKLOAD_API_SOCKET`, plus both the projected
`openshell-sa-token` volume and the `spiffe-workload-api` CSI volume.

If `grpcRoute.backendTLSPolicy.enabled=true`, the Gateway proxy validates the
backend pod's TLS certificate against a CA in a ConfigMap. Check that the
ConfigMap exists and contains the correct CA, that `enableMtls` is disabled,
and that the BackendTLSPolicy resource is present:

```bash
kubectl -n openshell get backendtlspolicy
kubectl -n openshell get configmap openshell-backend-ca -o yaml
helm -n openshell get values openshell | grep -E 'backendTLSPolicy|enableMtls|failOnTimeout|timeoutSeconds|caCertificateConfigMapName'
```

If the ConfigMap is missing after a cert-manager install, the post-install
certgen hook may have timed out waiting for cert-manager to issue the server
certificate. Check the certgen Job logs:

```bash
kubectl -n openshell get jobs | grep certgen
kubectl -n openshell logs job/openshell-certgen-backend-ca
```

Increase `pkiInitJob.timeoutSeconds` and run `helm upgrade` to retry. If the
Gateway proxy reports `TLS error: Secret is not supplied by SDS` or similar
backend TLS errors, the ConfigMap CA likely does not match the server
certificate CA — verify both are from the same issuer.
