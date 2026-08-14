---
name: debug-openshell-cluster
description: Debug why an OpenShell gateway deployment is unhealthy, unreachable, or unable to create sandboxes. Use for gateway health failures, Docker/Podman runtime issues, Helm failures, Kubernetes scheduling, TLS or auth, gateway interceptors, supervisor middleware startup or runtime failures, external compute-driver sockets, VM drivers, or sandbox startup. Trigger keywords - debug gateway, gateway failing, deployment failing, helm install failing, cluster health, gateway health, gateway not starting, health check failed, sandbox pending, docker driver, podman driver, kubernetes driver, external driver, compute driver socket, gateway interceptor, supervisor middleware, middleware failed, vm driver.
---

# Debug OpenShell Gateway Deployment

Diagnose a gateway and its selected compute platform. Do not assume OpenShell provisions Kubernetes or runs a k3s container. OpenShell targets a reachable gateway endpoint backed by Docker, Podman, Kubernetes, the experimental VM driver, or an operator-managed out-of-tree compute driver.

Use `openshell` first to identify the active endpoint. Then use the platform tools that match the gateway's compute driver: `docker`, `podman`, `kubectl`/`helm`, or VM driver logs.

## Overview

The target deployment flow is:

1. Operator starts or deploys the gateway with system packages, systemd, Helm, or a development task. The CLI does not start, stop, or destroy gateway services.
2. Operator configures the compute driver.
3. Operator provides the CLI and supervisor authentication material required by the deployment mode: edge or OIDC user auth, optional CLI mTLS, and gateway-minted sandbox JWTs.
4. The CLI registers a reachable gateway endpoint with `openshell gateway add`.
5. The gateway creates sandboxes through the selected compute driver.

For local evaluation only, TLS may be disabled and the gateway can be reached through `http://127.0.0.1:<port>`.

## Prerequisites

- The `openshell` CLI must be available for endpoint checks.
- Know the active gateway name and endpoint, or be able to inspect local gateway metadata.
- Know the compute platform: Docker, Podman, Kubernetes, VM, or an out-of-tree driver.
- For Kubernetes: `kubectl` must target the cluster that hosts OpenShell and Helm version 3 or later must be available.
- For Docker or Podman: the runtime socket must be reachable from the gateway host.

## Workflow

Run diagnostics in order and stop once the root cause is clear.

### Step 1: Check CLI Reachability

```bash
openshell gateway list --output json
openshell gateway info
openshell status
```

For a one-off endpoint check that bypasses stored gateway selection and metadata:

```bash
openshell --gateway-endpoint <url> status
```

Common findings:

- `No active gateway`: register one with `openshell gateway add <endpoint>`.
- Connection refused: gateway process is not running, service exposure is wrong, or a port-forward/proxy is not active.
- TLS/certificate errors: the endpoint scheme or trust chain is wrong, a local mTLS bundle does not match the gateway CA, or TLS termination does not match the gateway listener.
- `Unauthenticated` from an edge or OIDC gateway: refresh stored credentials with `openshell gateway login [name]`, then retry. Use `gateway logout` only when intentionally clearing local credentials.
- A direct development endpoint with a private or self-signed certificate can be isolated with `--gateway-endpoint <url> --gateway-insecure`; do not persist or recommend insecure verification for shared gateways.

### Step 2: Identify the Compute Platform

Use gateway metadata, deployment values, or the user's setup notes to identify the driver.

| Platform | Primary checks |
|---|---|
| Docker | Gateway process logs, Docker daemon health, sandbox containers, image pulls. |
| Podman | Podman socket, rootless networking, sandbox containers, image pulls. |
| Kubernetes | Helm release, gateway workload, service, secrets, sandbox pods, events. |
| VM | VM driver logs, rootfs availability, host virtualization support. |
| Extension | External driver process, Unix socket ownership/mode, configured driver name, capability handshake, gateway logs. |

### Step 3: Check Gateway Startup Dependencies

Before debugging the compute platform, inspect gateway logs for failures in dependencies initialized before the listener becomes ready.

For out-of-tree compute drivers, confirm the custom driver name and socket agree across CLI flags or `gateway.toml`, and that the operator-owned driver is running before the gateway starts:

```bash
rg -n 'compute_drivers|socket_path' /etc/openshell/gateway.toml
stat /run/openshell/<driver>.sock
journalctl -u <driver-service> --no-pager --lines=200
journalctl -u openshell-gateway --no-pager --lines=200
```

The custom driver name must not be a reserved built-in name (`docker`, `podman`, `kubernetes`, or `vm`). The socket must be accessible only to the intended gateway identity. Check gateway logs for connection errors, `GetCapabilities` failures, or an unexpected advertised driver name. The gateway does not create or supervise out-of-tree driver processes or sockets.

For configured gateway interceptors, inspect `[[openshell.gateway.interceptors]]`, their Unix or network endpoints, and gateway startup logs:

```bash
rg -n 'interceptors|provider_profile_sources|grpc_endpoint|tls_ca_cert_path|audience|allow_insecure_transport|binding_policy|failure_policy|gateway_jwt' /etc/openshell/gateway.toml
stat /run/openshell/interceptors/<name>.sock
journalctl -u <interceptor-service> --no-pager --lines=200
journalctl -u openshell-gateway --no-pager --lines=200
```

The gateway calls each interceptor's `Describe` RPC and validates its manifest at startup. Check for unreachable endpoints, invalid RPC/phase bindings, strict `allowlist` or `exact` mismatches, and `post_commit` bindings that resolve to `fail_closed`. If gateway JWT signing is enabled, authenticated network interceptors require HTTPS and a valid bearer token; check the private CA path, endpoint hostname, expected audience, issuer, `kid`, and interceptor logs for token rejection. `allow_insecure_transport = true` explicitly preserves unauthenticated plaintext behavior. If `provider_profile_sources` names an interceptor, that interceptor must advertise provider-profile capability and return a valid, duplicate-free catalog. A selected interceptor-only source is authoritative; include `builtin` or `user` sources explicitly when composition is intended.

For operator-run supervisor middleware, inspect `[[openshell.supervisor.middleware]]`, service reachability, and both gateway and supervisor logs:

```bash
rg -n 'supervisor|middleware|grpc_endpoint|tls_ca_cert_path|audience|allow_insecure_transport|max_payload_bytes|timeout|gateway_jwt' /etc/openshell/gateway.toml
journalctl -u <middleware-service> --no-pager --lines=200
journalctl -u openshell-gateway --no-pager --lines=200
openshell logs <sandbox-name> --tail --source sandbox
```

The middleware service must start before the gateway and be reachable from both the gateway and sandbox supervisors. Gateway startup fails if `Describe` is unavailable, a manifest exposes duplicate operation/phase bindings, the registration claims the reserved `openshell/` namespace, or payload and timeout limits are invalid. Supported V1 bindings are `HTTP_REQUEST/PRE_CREDENTIALS` and `WEBSOCKET_MESSAGE/PRE_CREDENTIALS`. When gateway JWT signing is disabled, supervisors preserve the legacy unauthenticated connector and do not request extension credentials. When signing is enabled, credential acquisition and verification failures are fail closed: check HTTPS trust and hostname validation, audience and issuer agreement, the token `kid`, gateway `RefreshSandboxToken` errors, and middleware logs. Changing a registration requires a gateway restart. A policy update can also fail before persistence if the selected implementation rejects its `network_middlewares` config.

At request time, distinguish attachment, binding selection, coverage, denial, and failure. A host-matched HTTP-only attachment can inspect the upgrade GET but does not join the WebSocket chain; the connection proceeds under either `on_error` mode and emits `binding_not_selected` coverage. A selected WebSocket stage receives text messages only. Binary messages pass under both modes, emit `unsupported_message_type` coverage, and consume a session sequence without an RPC. An explicit `middleware_denied` result is always enforced. WebSocket preflight returns `INSPECT`, voluntary `SKIP`, or authoritative `DENY`; `DENY` rejects the upgrade before upstream contact under both `on_error` modes. A selected-stage failure follows the policy-local `on_error`: `fail_closed` blocks the HTTP request or closes the WebSocket, while `fail_open` bypasses only that stage and emits a detection finding. A fail-open per-message capacity failure bypasses that message without disabling the stage. A timeout, transport failure, stream closure, missing or invalid response, duplicate or regressed sequence, or other failure that makes an established WebSocket stream unreliable disables that stage for later messages on the connection and emits `openshell.middleware.websocket_stage_disabled`. Confirm preflight, session-start, and session-end in service logs. OpenShell best-effort sends at most one session-end to each still-writable opened stage, including a preflight that terminates before session start; distinguish `MIDDLEWARE_DENIAL` from `MIDDLEWARE_FAILURE`. WebSocket message sequences are allocated session-wide; each stage receives a strictly increasing subset, so gaps are valid when binary messages or other units are not delivered to that stage. Zero, duplicate, or regressed sequences are protocol errors. If a running supervisor cannot install a new registry, it preserves its last-known-good generation and emits a configuration failure event.

For network policy validation failures, first distinguish a gateway mutation
rejection from a supervisor runtime rejection. Direct policy updates,
incremental merges and approvals, provider attachments, and provider-profile
fanout are validated against the complete effective policy before persistence
when the gateway knows the affected sandbox scope. A `FAILED_PRECONDITION`
ambiguity response means no invalid revision or partial fanout was stored.
Supervisor validation remains defense in depth for startup, races, and policy
sources outside those mutation paths.

Runtime rejection behavior is configured only in `gateway.toml`:

```toml
[openshell.gateway]
policy_validation_failure_mode = "fail_closed"
```

The default `fail_closed` mode deactivates the previous generation, closes
pinned relays, and quarantines new egress until a valid generation loads.
`retain_last_valid` explicitly keeps the previous valid policy active; without
one it still fails closed. Restart the gateway after changing this field.
Inspect sandbox OCSF configuration and finding events for the validation
rationale, configured and effective modes, active generation, and the explicit
`previous_policy_active` state.

### Step 4: Check Docker-Backed Gateways

```bash
docker info
docker ps --filter name=openshell
docker logs <container> --tail=200
docker run --rm --entrypoint /openshell-sandbox "${OPENSHELL_DOCKER_SUPERVISOR_IMAGE:-ghcr.io/nvidia/openshell/supervisor:latest}" --version
openshell status
```

For Docker GPU failures, check CDI support and NVIDIA CDI discovery separately:

```bash
docker info --format '{{json .CDISpecDirs}}'
docker info --format '{{json .DiscoveredDevices}}'
for dir in /etc/cdi /var/run/cdi; do
  if [ -d "$dir" ]; then
    find "$dir" -maxdepth 1 -type f \( -name '*.yaml' -o -name '*.json' \) -print
  else
    echo "$dir missing"
  fi
done
systemctl is-enabled nvidia-cdi-refresh.service nvidia-cdi-refresh.path || true
systemctl is-active nvidia-cdi-refresh.service nvidia-cdi-refresh.path || true
systemctl status nvidia-cdi-refresh.service nvidia-cdi-refresh.path --no-pager --lines=50
journalctl -u nvidia-cdi-refresh.service --no-pager --lines=100
```

When the NVIDIA Container Toolkit CDI refresh units are not enabled or no NVIDIA CDI spec has been generated, enable them and trigger a refresh:

```bash
sudo systemctl enable --now nvidia-cdi-refresh.path
sudo systemctl enable --now nvidia-cdi-refresh.service
sudo systemctl restart nvidia-cdi-refresh.service
docker info --format '{{json .DiscoveredDevices}}'
```

Common findings:

- Docker daemon unavailable: start Docker Desktop or Docker Engine.
- Gateway process stopped: inspect exit status and logs.
- Sandbox image missing or pull denied: verify image reference and registry credentials.
- Sandbox fails before readiness with an identity-resolution error: inspect the image's OCI `USER` and matching `/etc/passwd` and `/etc/group` entries, or explicitly set both process identity fields in policy. Root and missing identities are rejected.
- Sandbox fails before readiness with an OCI workspace validation error: inspect the image's `WorkingDir` using the immutable image ID reported by the gateway. Empty, `/`, and explicit `/sandbox` use the managed `/sandbox` compatibility workspace. Any other workdir must be an absolute normalized directory with no symlink components; the final policy UID, primary GID, and supplementary groups must pass the kernel's effective traverse/write checks, including POSIX ACL and LSM decisions. OpenShell does not create, chown, or chmod a non-default image workdir.
- Docker also rejects an image `VOLUME` that covers the workdir or one of its parents because the runtime would mask the immutable path before validation. Move the `VOLUME` below the workspace or remove the declaration.
- A workdir rejected as a special filesystem or OpenShell control-path collision cannot be made valid with permissions. Move the image workdir away from kernel-backed mounts and the concrete supervisor, TLS, token, runtime, and socket paths named in the error.
- Docker driver cannot initialize because it cannot find `openshell-sandbox`: verify `OPENSHELL_DOCKER_SUPERVISOR_BIN`, the sibling binary next to `openshell-gateway`, or the configured supervisor image contains `/openshell-sandbox`.
- Sandbox never registers: check gateway logs and supervisor callback endpoint.
- On macOS, repeated `Policy fetch failed after 5 attempts` messages with a
  Homebrew gateway bound to `[::1]:17670` indicate that the Docker
  `host-gateway` IPv4 route has no matching callback listener. Current releases
  leave `bind_address` unset in the Homebrew config, use the built-in
  `127.0.0.1:17670` primary listener, and reuse it for authenticated sandbox
  callbacks. On an older release, set `bind_address = "127.0.0.1:17670"` or
  upgrade.
- Supervisor image exits before printing `openshell-sandbox --version`: the image should be the scratch supervisor image from `deploy/docker/Dockerfile.supervisor` and must contain a static executable at `/openshell-sandbox`.
- `mise run e2e:docker:gpu` fails with `docker info --format json did not report any discovered NVIDIA CDI GPU devices`: Docker may report `CDISpecDirs` while still having no generated NVIDIA CDI specs. Verify `.DiscoveredDevices` contains entries such as `nvidia.com/gpu=all`, verify `/etc/cdi` or `/var/run/cdi` contains a generated NVIDIA spec, and check that `nvidia-cdi-refresh.service` and `nvidia-cdi-refresh.path` from NVIDIA Container Toolkit are enabled and healthy. The service is a one-shot unit, so `inactive (dead)` can be normal after a successful run; use `systemctl status` and `journalctl` to distinguish success from a skipped or failed refresh. NVIDIA recommends enabling the path and service units, and restarting `nvidia-cdi-refresh.service` to regenerate missing or stale CDI specs. If specs are generated but Docker still reports no discovered devices, restart Docker or reload the daemon and re-check `docker info`.

For source checkout development, restart the local gateway with:

```bash
mise run gateway:docker
```

### Step 5: Check Podman-Backed Gateways

```bash
podman info
podman ps --filter name=openshell
podman logs <container> --tail=200
openshell status
```

Common findings:

- Podman socket unavailable: start or expose the user socket.
- Rootless networking unavailable: inspect Podman network configuration.
- Sandbox image missing or pull denied: verify image reference and registry credentials.
- Sandbox fails before readiness with an identity-resolution error: inspect the image's OCI `USER` and matching `/etc/passwd` and `/etc/group` entries, or explicitly set both process identity fields in policy. Root and missing identities are rejected.
- Supervisor cannot call back: check callback endpoint and gateway logs.
- Gateway exits before becoming healthy with a callback-listener discovery
  error: inspect `podman info --debug`, the configured Podman network, and the
  host's IPv4 default route. Rootless pasta uses the private source address
  selected by that route; rootful Podman uses the bridge gateway address.
- Current gateways reuse the primary listener when it covers Podman's callback
  address. If the primary does not cover that address, inspect the gateway
  startup logs for the additional callback-only listener and its provenance.
- Rootless slirp4netns, another named helper, or missing helper metadata
  requires an explicitly remote `grpc_endpoint`. An explicit `host_gateway_ip`
  cannot bypass slirp4netns host-loopback isolation. Do not work around
  discovery failures by broadening the primary gateway listener to `0.0.0.0`.

### Step 6: Check Kubernetes Helm Gateways

```bash
helm -n openshell status openshell
helm -n openshell get values openshell
kubectl -n openshell get deployment,statefulset,pod,svc,pvc
kubectl -n openshell logs deployment/openshell -c openshell-gateway --tail=200
kubectl -n openshell logs statefulset/openshell -c openshell-gateway --tail=200
kubectl -n openshell rollout status deployment/openshell
kubectl -n openshell rollout status statefulset/openshell
```

Use the log and rollout commands for the workload kind that exists in the
release. Look for failed installs, unexpected values, missing namespace, wrong
image tag, TLS settings that do not match the registered endpoint, and
scheduling failures.

`server.telemetryEnabled` renders `OPENSHELL_TELEMETRY_ENABLED` on the gateway
pod, and the gateway propagates the effective value to sandbox supervisors.

When no external credential driver is enabled, the Helm chart uses the
gateway's default encrypted database credential storage. The chart creates a
retained Kubernetes Secret for the shared KEK, injects it into gateway pods, and
stores encrypted credential envelopes in the OpenShell database. For
`workload.kind=deployment` or multi-replica gateways, confirm
`server.externalDbSecret` points at a shared database. A render/install error
mentioning `server.credentialDrivers` means the values selected multiple
external credential backends.

For HA or PostgreSQL-backed installs, also check the external database Secret
referenced by `server.externalDbSecret` and the PostgreSQL workload if the test
or operator deployed one in-cluster:

```bash
kubectl -n openshell get secret openshell-ha-pg -o yaml
kubectl -n openshell get deployment,service,pod -l app.kubernetes.io/name=openshell-e2e-postgres
kubectl -n openshell logs deployment/openshell-e2e-postgres --tail=200
```

Check required Helm deployment secrets:

```bash
kubectl -n openshell get secret \
  openshell-server-tls \
  openshell-server-client-ca \
  openshell-client-tls \
  openshell-jwt-keys
```

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
the right trust anchor.  Only override this if you intentionally mount a
separate client CA via `server.tls.clientCaSecretName`.  Verify the mounted
client CA matches the CA that signed the client certificate:

```bash
kubectl -n openshell get statefulset openshell -o jsonpath='{.spec.template.spec.volumes[?(@.name=="tls-client-ca")]}' | jq .
# Should show items filter for ca.crt from openshell-server-tls
```

If `server.providerTokenGrants.spiffe.enabled=true`, the gateway should still
render `[openshell.gateway.gateway_jwt]` and mount the `sandbox-jwt` Secret.
SPIRE is used only by sandbox pods for dynamic provider token grants. Verify
that SPIRE is installed, the CSI driver is available, and the Kubernetes driver
config includes `provider_spiffe_workload_api_socket_path`:

```bash
helm -n openshell get values openshell | grep -E 'providerTokenGrants|workloadApiSocketPath'
kubectl get pods -A | grep -E 'spire|spiffe'
kubectl -n openshell get configmap openshell-config -o yaml | grep provider_spiffe_workload_api_socket_path
```

Sandbox pods using provider token grants should have an
`openshell.io/sandbox-id` annotation, an `openshell.ai/managed-by=openshell`
label, supervisor env vars `OPENSHELL_K8S_SA_TOKEN_FILE` and
`OPENSHELL_PROVIDER_SPIFFE_WORKLOAD_API_SOCKET`, plus both the projected
`openshell-sa-token` volume and the `spiffe-workload-api` CSI volume.

Check the image references currently used by the gateway deployment:

```bash
kubectl -n openshell get deployment openshell -o jsonpath="{.spec.template.spec.containers[*].image}{\"\n\"}{.spec.template.spec.containers[*].env[?(@.name==\"OPENSHELL_SUPERVISOR_IMAGE\")].value}{\"\n\"}"
kubectl -n openshell get statefulset openshell -o jsonpath="{.spec.template.spec.containers[*].image}{\"\n\"}{.spec.template.spec.containers[*].env[?(@.name==\"OPENSHELL_SUPERVISOR_IMAGE\")].value}{\"\n\"}"
helm -n openshell get values openshell | grep -E 'repository|tag|supervisorImage|workload'
```

The gateway image built from `deploy/docker/Dockerfile.gateway` and the scratch supervisor image built from `deploy/docker/Dockerfile.supervisor` should use the same build tag in branch and E2E deploys. A stale supervisor image can make sandbox behavior lag behind gateway policy or proto changes.

For local/external pull mode (the default local path via `mise run cluster`), local images are tagged to the configured local registry base, pushed to that registry, and pulled by k3s via the `registries.yaml` mirror endpoint. The `cluster` task pushes prebuilt local tags (`openshell/*:dev`, falling back to `localhost:5000/openshell/*:dev` or `127.0.0.1:5000/openshell/*:dev`).

Gateway image builds stage a partial Rust workspace from `deploy/docker/Dockerfile.images`. If cargo fails with a missing manifest under `/build/crates/...`, or an imported symbol exists locally but is missing in the image build, verify that every current gateway dependency crate, including `openshell-driver-docker`, `openshell-driver-kubernetes`, and `openshell-ocsf`, is copied into the staged workspace there.

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
kubectl -n openshell port-forward svc/openshell 8080:8080
openshell gateway add http://127.0.0.1:8080 --local --name local
openshell status
```

If the gateway is healthy but sandbox creation fails:

```bash
kubectl -n openshell get pods
kubectl -n openshell get events --sort-by=.lastTimestamp | tail -n 50
kubectl -n openshell logs deployment/openshell -c openshell-gateway --tail=200
kubectl -n openshell logs statefulset/openshell -c openshell-gateway --tail=200
```

Check the configured sandbox namespace:

```bash
helm -n openshell get values openshell | grep sandboxNamespace
```

Then inspect sandbox resources in that namespace.

Check the configured sandbox service account when TokenReview bootstrap or
sandbox registration fails. Helm creates a dedicated sandbox service account by
default and writes it to `[openshell.drivers.kubernetes].service_account_name`;
the gateway rejects projected tokens from other service accounts.

```bash
helm -n openshell get values openshell | grep -A3 sandboxServiceAccount
kubectl -n <sandbox-namespace> get serviceaccount openshell-sandbox
kubectl -n openshell get configmap openshell-config -o jsonpath='{.data.gateway\.toml}'
kubectl -n <sandbox-namespace> get sandbox <sandbox-name> -o jsonpath='{.spec.template.spec.serviceAccountName}{"\n"}'
```

If `topology = "sidecar"` is rendered under `[openshell.drivers.kubernetes]`,
sandbox pods should have an `openshell-network-init` init container running
`--mode=network-init`, an `agent` container running
`openshell-sandbox --mode=process`, and an `openshell-supervisor-network`
container running `--mode=network`. The init container owns nftables setup and
should be the only sidecar topology container with `NET_ADMIN`. It also needs
`CHOWN`/`FOWNER` to hand shared emptyDir state to the effective sidecar UID. The
default binary-aware network sidecar runs as UID 0 with primary GID
`sandbox_gid` and adds `SYS_PTRACE` plus `DAC_READ_SEARCH`. When
`process_binary_aware_network_policy = false`, it runs as the configured
non-root `proxy_uid` without those inspection capabilities. The pod `fsGroup`
is set to `sandbox_gid` in both modes.

In sidecar topology only the network sidecar should mount the gateway bootstrap
credentials (`openshell-sa-token` and `openshell-client-tls`). The process
container should not receive `OPENSHELL_ENDPOINT`, gateway TLS env vars, the
sandbox token file, or those credential mounts. Instead, the network sidecar
serves policy and provider environment state over the Unix control socket from
`OPENSHELL_SIDECAR_CONTROL_SOCKET` (`/run/openshell-sidecar/control.sock` by
default). The process supervisor must be the first and only client. After
validating its peer UID, GID, and PID, the sidecar unlinks the listener. If the
connection later closes, the network sidecar exits non-zero so Kubernetes can
restart it with a fresh listener. If the process supervisor fails before
launching the workload,
inspect both containers for control-socket bind, connect, bootstrap, or update
errors. If new SSH/exec sessions do not pick up refreshed provider environment,
inspect the network sidecar settings-poll logs and the process container logs
for provider environment update handling; the process container should consume
newer provider-env revisions without receiving gateway credentials.

The process container reports the workload entrypoint PID over the same control
socket, and the network sidecar uses that PID for binary-scoped policy
decisions through `/proc`. If rules with `policy.binaries` are unexpectedly
denied, inspect the sidecar control logs and confirm the pod has
`shareProcessNamespace: true`.
The shared state directory should preserve `sandbox_gid` inheritance
(`02775`). Sidecar SSH uses the Linux abstract socket
`@openshell-sidecar-ssh`; the network sidecar verifies its peer PID before
bridging gateway relay requests. No `ssh.sock` file should appear in the shared
state directory.
Inspect all three when sandbox registration or egress enforcement fails:

```bash
kubectl -n openshell get configmap openshell-config -o jsonpath='{.data.gateway\.toml}' | grep -E '^\[openshell\.drivers\.kubernetes\]|^topology\s*='
kubectl -n <sandbox-namespace> get pod <sandbox-pod> -o jsonpath='{range .spec.initContainers[*]}{.name}{" "}{.command}{"\n"}{end}'
kubectl -n <sandbox-namespace> get pod <sandbox-pod> -o jsonpath='{range .spec.containers[*]}{.name}{" "}{.command}{"\n"}{end}'
kubectl -n <sandbox-namespace> logs <sandbox-pod> -c openshell-network-init --tail=200
kubectl -n <sandbox-namespace> logs <sandbox-pod> -c openshell-supervisor-network --tail=200
kubectl -n <sandbox-namespace> logs <sandbox-pod> -c agent --tail=200
```

#### Corporate upstream proxy

When the deployment routes sandbox egress through a corporate HTTP forward
proxy, the operator-owned settings render under `[openshell.drivers.kubernetes]`
from the Helm `upstreamProxy` values. Absent proxy configuration preserves
direct-dial egress; any present-but-invalid value fails closed at gateway
startup (`validate_upstream_proxy_config`) rather than silently reverting to a
direct connection. Confirm the rendered configuration first:

```bash
kubectl -n openshell get configmap openshell-config -o jsonpath='{.data.gateway\.toml}' | grep -E 'https_proxy|no_proxy|proxy_auth_secret_(name|key)|proxy_auth_allow_insecure|proxy_connect_by_hostname'
helm -n openshell get values openshell | grep -A8 upstreamProxy
```

Only `http://host:port` forward proxies are supported; `https://` proxy URLs and
plain-HTTP egress are out of scope and rejected. Proxy credentials require
`topology = "sidecar"` — combined topology shares the credential mount with the
workload, so the gateway rejects credentials there. The credential Secret named
by `proxy_auth_secret_name` must exist in the sandbox namespace with the key
named by `proxy_auth_secret_key`, and Kubernetes will not create keys longer
than 253 bytes or named `.`/`..`.

The proxy arguments and credential mount are injected only into the container
that runs network supervision (the `agent` container in combined topology, the
`openshell-supervisor-network` sidecar in sidecar topology). The one-shot
`openshell-network-init` container and the process `agent` container in sidecar
topology must never receive them. The credential is projected read-only as the
`openshell-upstream-proxy-auth` volume at `/run/openshell/upstream-proxy-auth`
and passed as `--upstream-proxy-auth-file`; it must never appear in env,
annotations, or command arguments.

```bash
kubectl -n <sandbox-namespace> get secret <proxy-auth-secret> -o jsonpath='{.data}' >/dev/null && echo "secret present"
kubectl -n <sandbox-namespace> get pod <sandbox-pod> -o jsonpath='{range .spec.containers[*]}{.name}{" "}{.command}{"\n"}{end}' | grep -- '--upstream-'
kubectl -n <sandbox-namespace> get pod <sandbox-pod> -o jsonpath='{range .spec.containers[*]}{.name}{": "}{range .volumeMounts[*]}{.name}{" "}{end}{"\n"}{end}' | grep upstream-proxy-auth
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
kubectl -n <sandbox-namespace> logs <sandbox-pod> -c openshell-supervisor-network --tail=200 | grep -Ei 'upstream|connect|proxy'
```

### Step 7: Check VM-Backed Gateways

Use the VM driver logs and host diagnostics available in the user's environment. Verify:

- The VM driver process is running and reachable by the gateway.
- The runtime rootfs exists and matches the expected architecture.
- Host virtualization support is enabled.
- The sandbox supervisor can establish its callback connection to the gateway.

Then run:

```bash
openshell status
openshell logs <sandbox-name>
```

## Common Failure Patterns

| Symptom | Likely cause | Check |
|---|---|---|
| `openshell status` fails | Gateway endpoint unreachable or auth mismatch | `openshell gateway info`, gateway logs |
| Gateway starts but sandbox create fails | Compute driver cannot reach runtime | Docker/Podman/Kubernetes/VM driver logs |
| Gateway exits while resolving compute-driver listener requirements | Callback alias topology is unsupported, the Podman network cannot be inspected, or the selected address is not private/authorized | Gateway startup error, `podman info --debug`, Podman network inspection, host IPv4 default route |
| Admin, health, reflection, or HTTP request is denied on an additional Docker/Podman callback-only listener | Additional callback listeners intentionally expose only sandbox-callable gRPC methods | Retry through the gateway's primary endpoint; inspect the listener-purpose startup log if the address was unexpected |
| Docker or Podman sandbox never registers | Wrong callback endpoint or supervisor startup failure | Gateway logs and sandbox container logs |
| Docker GPU e2e fails before GPU sandbox comparison | NVIDIA CDI specs are missing or Docker has not discovered them | `docker info --format '{{json .DiscoveredDevices}}'`, `/etc/cdi`, `/var/run/cdi`, `nvidia-cdi-refresh.service` |
| Kubernetes gateway pod pending | PVC unbound, taint, selector, or insufficient resources | `kubectl -n openshell describe pod <pod>` |
| Kubernetes sandbox pod stuck pending, workspace PVC unbound | Cluster has no default `StorageClass` and OpenShell does not set `storageClassName` on the workspace PVC (clusters with a default `StorageClass` bind fine without it) | `kubectl -n openshell describe pvc`; set `server.workspaceStorageClass` (gateway config `workspace_storage_class`) to a valid `StorageClass` |
| Kubernetes gateway pod crash loops | Missing secret, bad DB URL, bad TLS config | `kubectl -n openshell logs deployment/openshell -c openshell-gateway` or `kubectl -n openshell logs statefulset/openshell -c openshell-gateway` |
| CLI TLS error | Local mTLS bundle does not match server cert/CA | Check `~/.config/openshell/gateways/<name>/mtls/` |
| Edge or OIDC gateway returns `Unauthenticated` | Stored login expired, audience/scopes mismatch, or gateway auth configuration changed | `openshell gateway info`, `openshell gateway login <name>`, gateway auth logs |
| Gateway fails before serving health after enabling an interceptor | Interceptor endpoint unavailable or manifest/binding validation failed | Gateway and interceptor logs; interceptor socket; `binding_policy`, phases, and failure policy |
| Authenticated interceptor or middleware rejects gateway calls | Private CA or hostname mismatch, expected audience or issuer mismatch, stale/unknown `kid`, or malformed extension token | `tls_ca_cert_path`, registration `audience`, service verifier config and logs; fetch well-known metadata only through the already-trusted gateway TLS endpoint |
| Provider profiles disappear after enabling an interceptor catalog | `provider_profile_sources` selected only an authoritative interceptor or returned invalid/duplicate IDs | Inspect source list and interceptor `Describe`/catalog logs; include `builtin` and `user` when intended |
| Gateway fails after registering supervisor middleware | Service unavailable, invalid manifest, duplicate binding, reserved name, or invalid payload/timeout limit | Middleware service and gateway logs; `[[openshell.supervisor.middleware]]`; `Describe` response |
| Policy update rejects `network_middlewares` | Unknown middleware name, implementation-owned config invalid, duplicate order, broad/invalid host selector, or fail-closed coverage of `tls: skip` | Policy error, gateway logs, middleware `ValidateConfig`, selector and order fields |
| Policy mutation returns `FAILED_PRECONDITION` for endpoint ambiguity | Equally specific effective endpoint selectors disagree on connection or request-processing metadata | CLI error, base and provider-composed policy, affected profile attachments; confirm no new revision was stored |
| Supervisor enters policy quarantine | A runtime candidate failed validation while `policy_validation_failure_mode = "fail_closed"` | Sandbox OCSF config/finding events, validation rationale, active generation, `previous_policy_active` |
| HTTP request returns `middleware_failed` or `middleware_denied`, or WebSocket closes with `1008` | Selected stage failed or explicitly denied admitted traffic | Sandbox OCSF logs; policy-local middleware config; service availability; binding operation; `on_error` |
| WebSocket upgrades but a host-matched middleware receives no preflight or message RPC | The implementation did not advertise `WEBSOCKET_MESSAGE/PRE_CREDENTIALS` | `WEBSOCKET_MIDDLEWARE_COVERAGE state=binding_not_selected`; service `Describe`; the upgrade GET may still have used its HTTP binding |
| Binary WebSocket message passes without a middleware RPC | Binary is unsupported by the V1 text-message binding under both `on_error` modes | `WEBSOCKET_MIDDLEWARE_COVERAGE state=unsupported_message_type`; the next text RPC may have a valid sequence gap |
| WebSocket messages stop reaching middleware after one failure | A fail-open stage stream was disabled for the rest of the connection | `openshell.middleware.websocket_stage_disabled`; middleware timeout/stream/protocol logs. A per-message capacity bypass alone leaves the stage active. Reconnect to create a fresh stream after a genuine stream failure |
| Supervisor repeatedly fails to install middleware after enabling gateway JWT signing | Extension credential minting, distribution, or authenticated service connection failed; last-known-good registry remains active | Gateway `RefreshSandboxToken` logs, sandbox configuration events, service token-verification logs, registration TLS/audience settings |
| Custom compute driver is unavailable | Driver process/socket missing, inaccessible, or configured with a reserved/mismatched name | Socket ownership/mode, driver service logs, gateway `GetCapabilities` logs |
| Sandbox remains `Stopping` or `Starting` | Driver stop/start failed, retained resource is missing, or a fresh supervisor has not connected | Gateway and driver logs; `docker inspect`, `podman inspect`, Agent Sandbox status/PVC, or VM state marker and launcher process |
| Image pull failure | Gateway or sandbox image cannot be pulled | Runtime events and image pull credentials |
| `K8s namespace not ready` with `envoy-gateway-openshell.yaml: the server could not find the requested resource` | Optional Gateway API manifest was applied without Envoy Gateway CRDs, or k3s Helm controller startup exceeded the namespace wait | Apply `deploy/kube/manifests/envoy-gateway-openshell.yaml` manually only after Envoy Gateway is installed and `grpcRoute` is enabled |
| HTTPS ingress (`grpcRoute.gateway.listener.protocol=HTTPS`) connection resets or TLS handshake hangs | Envoy terminates TLS but the gateway pod still expects TLS, so the plaintext backend hop fails | Set `server.disableTls=true` so Envoy forwards plaintext to the pod; verify the listener `certificateRefs` Secret exists in the release namespace and `openshell status` over `https://<host>` |
| HTTPS ingress returns `Unauthenticated` after connecting | TLS terminates at Envoy, so the gateway never sees a client cert; no OIDC issuer is configured for identity | Configure `server.oidc.issuer` and register with `openshell gateway add https://<host> --oidc-issuer <url>`, or set `server.auth.allowUnauthenticatedUsers=true` for a trusted-proxy/dev cluster |
| External server `Certificate` never becomes Ready with `certManager.serverIssuerRef` set | ACME issuer rejected internal-only SANs, a loopback IP, or a `commonName` absent from the SANs | `kubectl -n openshell describe certificate openshell-server-external`; confirm `certManager.serverDnsNames` lists only real, externally-resolvable hostnames |
| Sandbox supervisors fail TLS handshake with `UnknownCA` after configuring `certManager.serverIssuerRef` | `server.grpcEndpoint` is set to the external hostname, forcing supervisors to receive the ACME cert (via SNI) which they can't verify against chart CA | Remove `server.grpcEndpoint` or set it to the internal service name; supervisors should connect via internal service name to receive the internal cert |

## Reporting

When handing results back to the user, include:

- Active gateway endpoint and auth mode.
- Compute platform and driver.
- Gateway process or workload status.
- Recent gateway log summary.
- Missing or malformed TLS, OIDC/mTLS, or sandbox JWT material.
- Service exposure status.
- Sandbox workload status.
- The exact command that failed and the shortest fix.
