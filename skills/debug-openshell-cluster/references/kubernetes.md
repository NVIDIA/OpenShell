# Kubernetes Helm gateways

These checks also apply to OpenShift, which adds SecurityContextConstraints and, for external access, an OpenShift `Route`.

## Failure patterns

| Symptom | Likely cause | Check |
|---|---|---|
| Kubernetes gateway pod pending | PVC unbound, taint, selector, or insufficient resources | `kubectl -n openshell describe pod <pod>` |
| Kubernetes sandbox pod stuck pending, workspace PVC unbound | Cluster has no default `StorageClass` and OpenShell does not set `storageClassName` on the workspace PVC (clusters with a default `StorageClass` bind fine without it) | `kubectl -n openshell describe pvc`; set `server.workspaceStorageClass` (gateway config `workspace_storage_class`) to a valid `StorageClass` |
| Kubernetes gateway pod crash loops | Missing secret, bad DB URL, bad TLS config | `kubectl -n openshell logs deployment/openshell -c openshell-gateway` or `kubectl -n openshell logs statefulset/openshell -c openshell-gateway` |
| `helm upgrade` fails with an `autoscaling.*` message | HPA values invalid: missing `resources.requests` (or `resources.limits`), `maxReplicas` above 1 without `server.externalDbSecret` (or on a StatefulSet without `workload.allowMultiReplicaStatefulSet`), no metric target, or min/max out of order. "`minReplicas` and `maxReplicas` are not set" means `--reuse-values` kept a release without the chart's autoscaling defaults | Fix the values named in the error; upgrade with `--reset-then-reuse-values` instead of `--reuse-values` |
| HPA shows `<unknown>` targets | No metrics-server for CPU/memory, or the metrics adapter does not serve the custom metric | `kubectl -n openshell describe hpa openshell`, `kubectl get --raw /apis/custom.metrics.k8s.io/v1beta1` |
| One replica holds most sessions after a rollout | Expected: sessions stay where they reconnected | `openshell_server_supervisor_sessions` per pod; it fades as sandboxes are recreated |
| OpenShift gateway pod fails to start with an SCC/`runAsUser` error (e.g. `unable to validate against any security context constraint`) | Chart's default `podSecurityContext`/`securityContext` hardcodes `runAsUser`/`fsGroup`, which the restricted-v2 SCC rejects; it must instead inject the namespace-assigned UID/GID range | `oc -n openshell describe pod <pod>`; deploy with `podSecurityContext: null` and clear `securityContext.runAsUser` (see `deploy/helm/openshell/ci/values-openshift-scc.yaml`) |
| OpenShift sandbox pod fails to start (`unable to validate against any security context constraint`) | The `openshell-sandbox` service account lacks the privileged SCC it needs | `oc adm policy add-scc-to-user privileged -z openshell-sandbox -n openshell`; remove with `remove-scc-from-user` when done |
| OpenShift self-hosted Vault/OpenBao credential store pod never schedules (waits time out with `no matching resources found`) | The store's Helm chart pins `runAsUser`/`fsGroup`/seccomp, which restricted-v2 rejects, so the StatefulSet controller never creates the pod | Deploy the store's chart in its OpenShift mode (`--set global.openshift=true` for the OpenBao/Vault chart) so the namespace SCC assigns a compliant security context — no manual SCC grant needed |
| Vault credential driver returns HTTP 403 / `Vault Kubernetes auth denied the configured role` on provider create | Vault's `auth/kubernetes` method or the gateway login role is not provisioned, or the role is not bound to the gateway service account and namespace | In Vault: `bao auth enable kubernetes` and `bao write auth/kubernetes/config kubernetes_host=... kubernetes_ca_cert=@...`; ensure the login role's `bound_service_account_names`/`bound_service_account_namespaces` match the gateway SA and namespace and its policy grants the credential paths |
| Gateway API resources fail with `the server could not find the requested resource` | Optional Gateway API resources were applied without Gateway API CRDs | Install the standard Gateway API CRDs and selected controller, then enable `grpcRoute` before applying the optional ingress resources |
| A custom GatewayClass does not program the chart-created Gateway, or its proxy Service conflicts with the OpenShell Service | The selected controller is unavailable, or the default `grpcRoute.gateway.name` reuses the OpenShell Service name | Check `kubectl get gatewayclass,gateway,grpcroute -A`; set a distinct Gateway name such as `<fullname>-ingress`. For an existing Gateway, set `gateway.create=false` plus `gateway.name`, `gateway.namespace`, and optional `gateway.sectionName` |
| HTTPS ingress (`grpcRoute.gateway.listener.protocol=HTTPS`) connection resets or TLS handshake hangs | Envoy terminates TLS but the gateway pod still expects TLS, so the plaintext backend hop fails | Set `server.disableTls=true` so Envoy forwards plaintext to the pod; verify the listener `certificateRefs` Secret exists in the release namespace and `openshell status` over `https://<host>` |
| With `grpcRoute.replicaRouting.enabled=true`, sandbox SSH, forward, or exec still relay through a peer replica | A `<release>-replica-<i>` Service has no endpoint, so Envoy returns `Unavailable` and the CLI retries unrouted | `kubectl -n openshell get endpoints <release>-replica-0 <release>-replica-1`; confirm `workload.kind=statefulset` and the GRPCRoute status is `Accepted`/`ResolvedRefs` |
| HTTPS ingress returns `Unauthenticated` after connecting | TLS terminates at Envoy, so the gateway never sees a client cert; no OIDC issuer is configured for identity | Configure `server.oidc.issuer` and register with `openshell gateway add https://<host> --oidc-issuer <url>`, or set `server.auth.allowUnauthenticatedUsers=true` for a trusted-proxy/dev cluster |
| External server `Certificate` never becomes Ready with `certManager.serverIssuerRef` set | ACME issuer rejected internal-only SANs, a loopback IP, or a `commonName` absent from the SANs | `kubectl -n openshell describe certificate openshell-server-external`; confirm `certManager.serverDnsNames` lists only real, externally-resolvable hostnames |
| Sandbox supervisors fail TLS handshake with `UnknownCA` after configuring `certManager.serverIssuerRef` | `server.grpcEndpoint` is set to the external hostname, forcing supervisors to receive the ACME cert (via SNI) which they can't verify against chart CA | Remove `server.grpcEndpoint` or set it to the internal service name; supervisors should connect via internal service name to receive the internal cert |
| Browser `ERR_BAD_SSL_CLIENT_AUTH_CERT` or gateway logs show client cert verification when OIDC or direct HTTPS is expected | Listener client-CA verification still enabled (`clientCaSecretName` unset or `client_ca_path` in ConfigMap) | Set `server.tls.clientCaSecretName=""`, upgrade chart, confirm ConfigMap omits `client_ca_path` |

## Checks

```bash
helm -n openshell status openshell
helm -n openshell get values openshell
kubectl -n openshell get deployment,statefulset,pod,svc,pvc
GATEWAY_DEPLOYMENT="$(kubectl -n openshell get deployment openshell >/dev/null 2>&1 && echo deployment/openshell || echo statefulset/openshell)"
kubectl -n openshell logs "${GATEWAY_DEPLOYMENT}" -c openshell-gateway --tail=200
kubectl -n openshell rollout status "${GATEWAY_DEPLOYMENT}"
```

Use the log and rollout commands for the gateway resource kind that exists in
the release. Look for failed installs, unexpected values, missing namespace, wrong
image tag, TLS settings that do not match the registered endpoint, and
scheduling failures.

When checking a Helm values migration, compare the rendered `gateway.toml`
with the intended `gatewayConfig` tables. Explicit resource-admission settings
and the Kubernetes Secrets credential namespace take precedence over deprecated
aliases. Confirm the credential driver's namespace matches its Role and
RoleBinding. An unset workload `image_pull_policy` uses Kubernetes defaults;
the global Helm pull policy applies to runtime and supervisor images.

The chart mounts the `gateway.toml` ConfigMap key directly at
`/etc/openshell/gateway.toml` as a read-only `subPath` file. This avoids the
atomic-writer symlink exposed by a ConfigMap directory mount because the gateway
rejects symlinked configuration. A checksum pod-template annotation rolls the
workload when the ConfigMap changes. If config preflight reports a symlink or
nonregular path, inspect the rendered mount and confirm the workload rolled to
the current chart revision:

```bash
kubectl -n openshell get deployment,statefulset -o yaml | rg -n 'gateway-config|mountPath|subPath|checksum/gateway-config'
kubectl -n openshell rollout status <deployment-or-statefulset>/openshell
kubectl -n openshell logs <gateway-pod> -c openshell-gateway --tail=200
```

`server.telemetryEnabled` renders `OPENSHELL_TELEMETRY_ENABLED` on the gateway
pod, and the gateway propagates the effective value to sandbox supervisors.

When no external credential driver is enabled, the Helm chart uses the
gateway's default encrypted database credential storage. The chart creates a
retained Kubernetes Secret for the shared KEK, injects it into gateway pods, and
stores encrypted credential envelopes in the OpenShell database. For
`workload.kind=deployment` or multi-replica gateways, confirm
`server.externalDbSecret` points at a shared database. A render/install error
mentioning multiple credential drivers means the
`gatewayConfig.openshell.gateway.credential_drivers` list selected more than
one external credential backend.

For HA or PostgreSQL-backed installs, also check the external database Secret
referenced by `server.externalDbSecret` and the PostgreSQL workload when it is
deployed in-cluster:

```bash
kubectl -n <namespace> get secret <external-db-secret> -o yaml
kubectl -n <namespace> get deployment,service,pod -l app.kubernetes.io/name=<postgres-workload>
kubectl -n <namespace> logs deployment/<postgres-workload> --tail=200
```

Multi-replica gateways serialize cross-object sandbox and provider mutations
with a PostgreSQL advisory lock. If those RPCs stall while ordinary reads and
health checks remain responsive, inspect long-running database sessions and
advisory-lock waiters. Do not print the database URI or Secret contents into
logs:

```sql
SELECT pid, granted, waitstart
FROM pg_locks
WHERE locktype = 'advisory';
```

For multi-replica peer relay, per-replica capacity, TLS secrets, cert-manager, SPIFFE, or backend TLS problems, read [kubernetes-tls-and-replicas.md](kubernetes-tls-and-replicas.md).

Check the image references currently used by the gateway deployment:

```bash
GATEWAY_DEPLOYMENT="$(kubectl -n openshell get deployment openshell >/dev/null 2>&1 && echo deployment/openshell || echo statefulset/openshell)"
kubectl -n openshell get "${GATEWAY_DEPLOYMENT}" -o jsonpath="{.spec.template.spec.containers[*].image}{\"\n\"}{.spec.template.spec.containers[*].env[?(@.name==\"OPENSHELL_SUPERVISOR_IMAGE\")].value}{\"\n\"}"
helm -n openshell get values openshell | grep -E 'repository|tag|supervisorImage|workload'
```

The gateway, sandbox, and supervisor images should use the same release tag. A stale runtime image can make sandbox behavior lag behind gateway policy or protocol changes. Kubernetes sandboxes take the configured supervisor and runtime images each time they start, so a sandbox that kept running through an upgrade uses its previous images until its next stop and start.

For vulnerability reports, record the running image digest and scan that exact
artifact. The gateway includes a pinned Distroless base; the supervisor includes
Alpine packages updated at image build time. A dependency or base-image fix only
reaches deployed containers after rebuilding, publishing, and redeploying the
images. Compare findings against the SBOM for that digest, not just its mutable
`latest` or `dev` tag.
For gateway base refreshes, verify the installed libc package revision in each
platform's SBOM; the binary's glibc compatibility floor is not its runtime version.

For plaintext local evaluation, confirm the chart has:

```bash
helm -n openshell get values openshell | grep -E 'disableTls|grpcEndpoint'
```

Expected shape:

```yaml
server:
  disableTls: true
  grpcEndpoint: http://openshell.openshell.svc.cluster.local:8080
```

Check service exposure:

```bash
kubectl -n openshell get svc openshell -o wide
kubectl -n openshell get endpoints openshell
```

For local port-forward testing:

```bash
kubectl -n openshell port-forward service/openshell 8080:8080
```

Leave the port forward running. In another terminal, register the local endpoint if needed and verify it:

```bash
openshell gateway add http://127.0.0.1:8080 --local --name local-kubernetes
openshell status
```

If the gateway is healthy but sandbox creation fails:

```bash
kubectl -n openshell get pods
kubectl -n openshell get events --sort-by=.lastTimestamp | tail -n 50
GATEWAY_DEPLOYMENT="$(kubectl -n openshell get deployment openshell >/dev/null 2>&1 && echo deployment/openshell || echo statefulset/openshell)"
kubectl -n openshell logs "${GATEWAY_DEPLOYMENT}" -c openshell-gateway --tail=200
```

Check the configured sandbox namespace:

```bash
helm -n openshell get values openshell | grep sandboxNamespace
```

Then inspect sandbox resources in that namespace.

For a split release, the gateway values should have
`workspaceResources.enabled=false`, and the target namespace should contain a
separate `openshell-workspace` release:

```bash
helm -n openshell get values openshell | grep -A2 workspaceResources
helm -n <sandbox-namespace> status openshell-workspace
kubectl -n <sandbox-namespace> get serviceaccount,role,rolebinding,networkpolicy \
  -l app.kubernetes.io/instance=openshell-workspace
kubectl auth can-i create sandboxes.agents.x-k8s.io \
  --namespace <sandbox-namespace> \
  --as system:serviceaccount:openshell:openshell
```

If the gateway cannot create or watch sandboxes, verify the workspace
RoleBinding subject matches the gateway ServiceAccount name and namespace.
If SSH relay connections fail, verify the workspace NetworkPolicy selects the
gateway's actual `app.kubernetes.io/name` and
`app.kubernetes.io/instance` labels.

Check the configured sandbox service account when TokenReview bootstrap or
sandbox registration fails. Helm creates a dedicated sandbox service account by
default and writes it to `[openshell.drivers.kubernetes].service_account_name`;
the selected Kubernetes compute driver rejects projected tokens from other
service accounts. For an external driver, inspect its logs and confirm it
advertises `supports_sandbox_authentication`; the gateway delegates the opaque
credential over the driver socket and never interprets Kubernetes settings.
Drivers that advertise sandbox authentication must return the same non-empty
runtime identity from sandbox creation and credential authentication. A
gateway log reporting a compute runtime identity mismatch indicates stale or
re-created runtime resources; compare the live resource UID with the sandbox
that the gateway provisioned. Restart also rejects multiple Sandbox resources
with the same sandbox label and requires the persisted namespace and CR UID to
remain unchanged. A generation-bound session-token rejection usually means the
supervisor is presenting credentials from a runtime that was replaced; inspect
the persisted generation before retrying bootstrap.

The Kubernetes driver serializes lifecycle mutations and runtime reconciliation
per sandbox within one driver instance. A busy sandbox is checked again on the
next reconciliation pass. If restart still loses its supervisor, compare the
Sandbox and Pod UIDs and identify which gateway or external driver process
performed cleanup; the local mutation gate does not coordinate separate processes.

```bash
helm -n openshell get values openshell | grep -A3 sandboxServiceAccount
kubectl -n <sandbox-namespace> get serviceaccount openshell-sandbox
kubectl -n openshell get configmap openshell-config -o jsonpath='{.data.gateway\.toml}'
kubectl -n <sandbox-namespace> get sandbox <sandbox-name> -o jsonpath='{.spec.template.spec.serviceAccountName}{"\n"}'
```

The Kubernetes driver creates a sandbox workload Pod and a separate, directly
managed supervisor Pod. The cluster CNI must enforce ingress and egress
Kubernetes NetworkPolicy in every sandbox namespace; the Kubernetes API cannot
attest enforcement. Run sandboxes only in a trusted namespace
where tenants cannot create Pods, copy OpenShell role labels, or read the
bootstrap Secret.

The workload Pod runs `/openshell-sandbox`. It has no gateway credentials and
no direct egress. One namespace-wide workload NetworkPolicy is created before
the suspended Sandbox resource. It denies all workload egress and allows
supervisor Pods to reach sandbox TLS listeners. The driver then creates a
per-sandbox Service, split immutable bootstrap Secrets, and a gated supervisor
Pod before releasing either Pod. The supervisor Pod runs
`/openshell-supervisor`. Both Pods use the
same resolved non-root identity, request no capabilities, drop `ALL`, disable
privilege escalation, and use `RuntimeDefault` seccomp. The supervisor reaches
the sandbox over per-sandbox TLS with server-certificate verification plus
bootstrap-token client authentication, and owns gateway policy, provider
credentials, DNS, and mediated upstream connections.

Inspect all driver-managed resources when a Kubernetes sandbox remains Starting
or loses readiness:

```bash
kubectl -n <sandbox-namespace> get sandbox,pod,service,secret -l openshell.ai/sandbox-id=<sandbox-id>
kubectl -n <sandbox-namespace> get networkpolicy openshell-sandbox-workloads -o yaml
kubectl -n <sandbox-namespace> describe pod -l openshell.ai/sandbox-id=<sandbox-id>,openshell.ai/boundary-role=supervisor
kubectl -n <sandbox-namespace> logs pod/<supervisor-pod> --tail=200
kubectl -n <sandbox-namespace> get pod -l openshell.ai/sandbox-id=<sandbox-id>,openshell.ai/boundary-role=workload -o yaml
kubectl -n <sandbox-namespace> get networkpolicy -l openshell.ai/sandbox-id=<sandbox-id> -o yaml
```

Creation and recovery fail closed. A missing Secret leaves both pods inert; a
missing or unobserved workload fence must prevent the driver from releasing the
Sandbox; and readiness requires both Agent Sandbox readiness and an Available
supervisor Pod. Its exec readiness check succeeds only after the
supervisor has attached, confirmed enforcement, started or resumed the
workload, and registered the gateway access plane. Use both Pod logs for
bootstrap errors. An `EPERM` during enforcement setup means the runtime blocked
a required unprivileged seccomp, task-memory, or Landlock operation. Do not add
capabilities, gateway egress, or credentials to the workload Pod as a
workaround.

If a Sandbox remains in the `releasing` bootstrap phase, inspect the supervisor
Pod first. The gateway keeps the workload running during this phase so the
supervisor can release that sandbox's runtime-control relationship cleanly.
Check the Pod's deletion timestamp, termination grace period, events, and
finalizers, and verify that the gateway ServiceAccount can delete Pods in the
sandbox namespace:

```bash
kubectl -n <sandbox-namespace> get pod \
  -l openshell.ai/sandbox-id=<sandbox-id>,openshell.ai/boundary-role=supervisor \
  -o yaml
kubectl auth can-i delete pods \
  --namespace <sandbox-namespace> \
  --as system:serviceaccount:openshell:openshell
```

Do not suspend or delete the workload Pod manually. The driver advances to
`suspending` only after runtime control has been released, and then suspends the
workload.

If a Sandbox remains in the `suspending` bootstrap phase, verify that the
gateway ServiceAccount can create and delete Secrets in the sandbox
namespace. In operator mode, those permissions come only from the
`openshell-workspace` chart installed in the namespace. Recovery deletes the
recorded generation's bootstrap Secrets by name before clearing the suspension
annotations:

```bash
for verb in create delete; do
  kubectl auth can-i "$verb" secrets \
    --namespace <sandbox-namespace> \
    --as system:serviceaccount:openshell:openshell
done
```

Any `no` result can strand recovery before workload Pod creation. Upgrade the
OpenShell chart rather than treating missing workload Pods as Pod failures.

## Corporate upstream proxy

When the deployment routes sandbox egress through a corporate HTTP forward
proxy, the operator-owned settings render under `[openshell.drivers.kubernetes]`
from the Helm `upstreamProxy` values. Absent proxy configuration preserves
direct-dial egress; any present-but-invalid value fails closed at gateway
startup (`validate_upstream_proxy_config`) rather than silently reverting to a
direct connection. Confirm the rendered configuration first:

```bash
kubectl -n openshell get configmap openshell-config -o jsonpath='{.data.gateway\.toml}' | grep -E 'https_proxy|no_proxy|proxy_auth_secret_(name|key)|proxy_auth_allow_insecure|proxy_connect_by_hostname|proxy_ca_bundle'
helm -n openshell get values openshell | grep -A12 upstreamProxy
```

Both `http://host:port` and `https://host:port` forward proxies are supported;
plain-HTTP egress is out of scope and always dials directly. The credential
Secret named by `proxy_auth_secret_name` must exist in the sandbox namespace
with the key named by `proxy_auth_secret_key`, and Kubernetes will not create
keys longer than 253 bytes or named `.`/`..`.

An `https://` proxy with a private CA, or a TLS-intercepting proxy, also needs
`upstreamProxy.caBundle.configMapName`. That ConfigMap lives in the **gateway's**
release namespace, not the sandbox namespace, and the gateway reads it and
stages the bundle into each sandbox's supervisor bootstrap Secret. A missing
ConfigMap leaves the gateway Pod in `ContainerCreating`, like `oidc-ca` and
`vault-ca`:

```bash
kubectl -n openshell get configmap <proxy-ca-configmap> -o jsonpath='{.data}' >/dev/null && echo "CA ConfigMap present"
kubectl -n openshell describe pod -l app.kubernetes.io/name=openshell | grep -A5 'ContainerCreating\|MountVolume'
kubectl -n <sandbox-namespace> get secret <supervisor-bootstrap-secret> -o jsonpath='{.data.upstream-proxy-ca\.pem}' | head -c 20
```

An empty last command with `proxy_ca_bundle` set in the rendered TOML means the
bundle never reached the sandbox; check the gateway logs for a `proxy_ca_bundle`
error, which fails closed at startup rather than falling back to direct egress.

The proxy arguments and credential mount belong only to the separate supervisor
Pod. The workload Pod must never receive them. The credential is projected
read-only as `openshell-upstream-proxy-auth` at
`/run/openshell/upstream-proxy-auth` and passed by file path; it must never
appear in environment variables, annotations, or command arguments.

```bash
kubectl -n <sandbox-namespace> get secret <proxy-auth-secret> -o jsonpath='{.data}' >/dev/null && echo "secret present"
kubectl -n <sandbox-namespace> get pod <supervisor-pod> -o jsonpath='{.spec.containers[0].command}' | grep -- '--upstream-'
kubectl -n <sandbox-namespace> get pod <supervisor-pod> -o jsonpath='{.spec.containers[0].command}' | grep -- '--upstream-proxy-ca-bundle'
kubectl -n <sandbox-namespace> get pod <supervisor-pod> -o jsonpath='{.spec.containers[0].volumeMounts}' | grep upstream-proxy-auth
kubectl -n <sandbox-namespace> get events --sort-by=.lastTimestamp | grep -Ei 'secret|MountVolume' | tail -n 20
```

A missing Secret or wrong key leaves the pod stuck with a
`MountVolume.SetUp failed` / `secret ... not found` event. If the pod starts but
egress still fails, the corporate proxy itself is the next suspect: policy-
approved TLS CONNECT requests that time out after policy evaluation usually mean
the proxy URL is unreachable from the sandbox namespace, or a cluster-internal
destination that should be direct is missing from `no_proxy`. Inspect the
network supervisor logs for CONNECT and upstream-proxy decisions:

```bash
kubectl -n <sandbox-namespace> logs pod/<supervisor-pod> --tail=200 | grep -Ei 'upstream|connect|proxy'
```
