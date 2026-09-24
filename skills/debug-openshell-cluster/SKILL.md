---
name: debug-openshell-cluster
description: Debug why an OpenShell gateway deployment is unhealthy, unreachable, or unable to create sandboxes. Use for gateway health failures, Docker/Podman runtime issues, Helm failures, Kubernetes scheduling, TLS or auth, gateway interceptors, supervisor middleware startup or runtime failures, external compute-driver sockets, VM drivers, or sandbox startup. Trigger keywords - debug gateway, gateway failing, deployment failing, helm install failing, cluster health, gateway health, gateway not starting, health check failed, sandbox pending, docker driver, podman driver, kubernetes driver, external driver, compute driver socket, gateway interceptor, supervisor middleware, middleware failed, vm driver.
---

# Debug OpenShell Gateway Deployment

Diagnose a gateway and its selected compute platform. Do not assume OpenShell provisions Kubernetes or runs a k3s container. OpenShell targets a reachable gateway endpoint backed by Docker, Podman, Kubernetes, the experimental VM driver, or an operator-managed out-of-tree compute driver.

Use `openshell` first to identify the active endpoint. Then use the platform tools that match the gateway's compute driver: `docker`, `podman`, `kubectl`/`helm`, or VM driver logs.

## Overview

The target deployment flow is:

1. Operator starts or deploys the gateway with system packages, systemd, or Helm. The CLI does not start, stop, or destroy gateway services.
2. Operator configures the compute driver.
3. Operator provides the CLI and supervisor authentication material required by the deployment mode: edge or OIDC user auth, optional CLI mTLS, and gateway-minted sandbox JWTs.
4. The CLI registers a reachable gateway endpoint with `openshell gateway add`.
5. The gateway creates sandboxes through the selected compute driver.

The `openshell-gateway` composition crate explicitly installs its compiled
Docker, Podman, Kubernetes, and VM registrations at startup; `openshell-server`
does not link compute-driver crates. Custom gateway binaries may include a
subset of those registrations. With no configured driver, the gateway probes only
installed registrations in priority order (Kubernetes, Podman, then Docker);
VM has no probe and remains opt-in. Confirm the binary's registered drivers
when auto-detection reports that no suitable driver is available. If
configuration selects a driver that was not compiled in, the gateway treats
the name as an external driver and reports a missing `socket_path` unless an
endpoint is configured.

On Windows, custom binaries can include MXC independently. Registrations for
Docker, Podman, Kubernetes, and VM are rejection stubs when included; they do
not enable those runtimes on Windows.

See the [compute driver reference](https://docs.nvidia.com/openshell/latest/reference/sandbox-compute-drivers.md)
for selective-build options and external-driver configuration.

For local evaluation only, TLS may be disabled and the gateway can be reached through `http://127.0.0.1:<port>`.

## Prerequisites

- The `openshell` CLI must be available for endpoint checks.
- Know the active gateway name and endpoint, or be able to inspect local gateway metadata.
- Know the compute platform: Docker, Podman, Kubernetes, VM, or an out-of-tree driver.
- For Kubernetes: `kubectl` must target the cluster that hosts OpenShell and Helm version 3 or later must be available.
- For Docker or Podman: the runtime socket must be reachable from the gateway host.

Use `openshell --help` and nested `--help` output as the authority for the installed CLI version. Use the published [installation guide](https://docs.nvidia.com/openshell/latest/about/installation.md), [compute-driver reference](https://docs.nvidia.com/openshell/latest/reference/sandbox-compute-drivers.md), [gateway configuration reference](https://docs.nvidia.com/openshell/latest/reference/gateway-config.md), and [Kubernetes setup guide](https://docs.nvidia.com/openshell/latest/kubernetes/setup.md) as the authority for deployment and configuration behavior.

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
| OpenShift | Same as Kubernetes, plus SecurityContextConstraints (SCCs) and, for external access, an OpenShift `Route`. Detect OpenShift by the presence of the `route.openshift.io` API group (`oc api-resources --api-group=route.openshift.io`). |
| VM | VM driver logs, rootfs availability, host virtualization support. |
| Extension | External driver process, Unix socket ownership/mode, configured driver name, capability handshake, gateway logs. |

### Step 3: Check Gateway Startup Dependencies

Before debugging the compute platform, inspect gateway logs for failures in dependencies initialized before the listener becomes ready.

For resource-admission failures, distinguish disabled caller driver config from
missing resource approval. Helm defaults `server.drivers.kubernetes.allowDriverConfig`
to false and `resourceAdmission.enabled` to true. Existing PVCs, RuntimeClasses,
and PriorityClasses need matching administrator-owned labels; namespace
membership and read-only access do not grant approval. GPU devices and
operator-selected image-pull Secrets do not need admission labels. In managed
mode, inspect the configured source image-pull Secret in the gateway namespace
and the generation copies (`openshell.ai/component=image-pull`) in the workspace
namespace. Legacy workloads without
admission provenance need recreation. Do not
automatically label control-plane resources or disable enforcement as a repair.

For out-of-tree compute drivers, also check that their versioned admission-policy
acknowledgement matches the gateway's policy. Configure standalone driver policy
through its administrator-owned `--admission-config-json` option.

For out-of-tree compute drivers, confirm the selected driver name and socket agree across CLI flags or `gateway.toml`, and that the operator-owned driver is running before the gateway starts:

```bash
rg -n '^version|compute_driver|socket_path|guest_tls_' /etc/openshell/gateway.toml
stat /run/openshell/<driver>.sock
journalctl -u <driver-service> --no-pager --lines=200
journalctl -u openshell-gateway --no-pager --lines=200
```

Gateway configuration requires `[openshell] version = 2`, a singular
`compute_driver` selector, and driver-owned settings under
`[openshell.drivers.<name>]`. The gateway rejects legacy `compute_drivers` and
`--drivers` selectors rather than silently migrating them. One valid, nonempty
`OPENSHELL_DRIVERS` value remains a deprecated environment-only alias when the
canonical selector is absent; the gateway selects that driver with a warning.
Empty, invalid, comma-delimited, or conflicting values fail startup. Homebrew
and RPM package startup migrates only exact package-generated v1 defaults. If
an upgraded package still reports an unsupported version, inspect the active prefix or `~/.config/openshell/gateway.toml`; an edited v1 file must
follow the published schema-v2 migration steps and must not be overwritten.
Guest TLS CA, certificate, and key paths are the exception to driver ownership:
configure the complete bundle under `[openshell.gateway]`, and the gateway
injects it only into the selected local driver. TLS-enabled Docker, Podman, and
VM drivers fail startup when neither those paths nor the package-managed local
bundle is available; Kubernetes projects its bundle through a Secret.

Custom names use `[openshell.drivers.<name>].socket_path`. A launch-time `--compute-driver-socket` override may also use `docker`, `podman`, `kubernetes`, or `vm`; the endpoint then takes precedence over built-in construction. First-party standalone drivers require the socket parent directory to be owned by the driver's effective UID, force its mode to `0700`, create the socket with mode `0600`, and accept only peers with that same UID. Check the parent and socket separately with `stat`; a gateway running under a different UID cannot connect even when filesystem permissions or group membership would otherwise allow it. Operator-supplied drivers must provide equivalent access control appropriate to their implementation. Check gateway logs for connection errors, `GetCapabilities` failures, missing peer metadata, protocol-major mismatch, unmet required capabilities, or an unexpected advertised driver name. `openshell gateway info` reports successful startup negotiations. The advertised name is diagnostic metadata; negotiated features control optional behavior. The gateway does not create or supervise operator-supplied driver processes or sockets.

For the Kubernetes Secrets credential driver, every provider credential lives in
the configured `namespace`, in every workspace mode. A `PermissionDenied` error
naming another namespace means the provider's credential handle points outside
the configured namespace; recreate the provider. An `unknown field` startup
error for `[openshell.credential_drivers.kubernetes-secrets]` means the table
sets a key the driver does not accept. Confirm the gateway can reach the
credential namespace:

```bash
kubectl -n openshell get configmap openshell-config -o jsonpath='{.data.gateway\.toml}' | grep -A3 '^\[openshell\.credential_drivers\.kubernetes-secrets\]'
kubectl auth can-i get secrets -n <credential-namespace> --as system:serviceaccount:openshell:openshell
```

For a configured Vault credential driver, inspect its endpoint and trust bundle
before debugging provider resolution. Non-loopback addresses must use HTTPS,
and the driver never follows redirects. A private CA bundle augments platform
roots but does not disable hostname verification. With Helm,
`server.credentialDrivers.vault.caConfigMapName` names a ConfigMap whose
`ca.crt` key is mounted at `/etc/openshell-tls/vault-ca/ca.crt`:

```bash
kubectl -n openshell get configmap openshell-config -o jsonpath='{.data.gateway\.toml}' | grep -A10 '^\[openshell\.credential_drivers\.vault\]'
kubectl -n openshell get pod -l app.kubernetes.io/name=openshell -o jsonpath='{range .items[0].spec.containers[0].volumeMounts[*]}{.name}{" "}{.mountPath}{"\n"}{end}' | grep vault-ca
kubectl -n openshell get configmap <vault-ca-configmap> -o jsonpath='{.data.ca\.crt}' | openssl x509 -noout -subject -issuer -dates
kubectl -n openshell logs statefulset/openshell -c openshell-gateway --tail=200
```

An HTTP service DNS address fails configuration validation. `UnknownIssuer` or
an invalid CA error means the ConfigMap is missing, the `ca.crt` key is wrong,
or the bundle does not contain the Vault server's issuer. A hostname mismatch
means the HTTPS `address` host is absent from the server certificate SANs; keep
verification enabled and issue a certificate for the service DNS name.

For configured gateway interceptors, inspect `[[openshell.gateway.interceptors]]`, their Unix or network endpoints, and gateway startup logs:

```bash
rg -n 'interceptors|provider_profile_sources|grpc_endpoint|tls_ca_cert_path|audience|allow_insecure_transport|binding_policy|failure_policy|gateway_jwt' /etc/openshell/gateway.toml
stat /run/openshell/interceptors/<name>.sock
journalctl -u <interceptor-service> --no-pager --lines=200
journalctl -u openshell-gateway --no-pager --lines=200
```

The gateway calls each interceptor's `Describe` RPC and validates its manifest at startup. Check for missing peer metadata, protocol-major mismatch, unmet required capabilities, unreachable endpoints, invalid RPC/phase bindings, strict `allowlist` or `exact` mismatches, and `post_commit` bindings that resolve to `fail_closed`. If gateway JWT signing is enabled, authenticated network interceptors require HTTPS and a valid bearer token; check the private CA path, endpoint hostname, expected audience, issuer, `kid`, and interceptor logs for token rejection. `allow_insecure_transport = true` explicitly preserves unauthenticated plaintext behavior. If `provider_profile_sources` names an interceptor, that interceptor must advertise provider-profile capability and return a valid, duplicate-free catalog. A selected interceptor-only source is authoritative; include a `user` source explicitly when composition is intended. The `builtin` source type was removed: a config that still names it is rejected at startup.

If the deployment uses supervisor middleware, follow the
[supervisor middleware troubleshooting reference](references/supervisor-middleware.md)
for startup, authentication, policy validation, and HTTP or WebSocket failures.

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

The published supervisor image uses a shell-free distroless Debian 13 base.
Use container logs, engine inspection and the configured exec health probe for
diagnostics; `exec ... sh`, package installation and in-container shell scripts
are unavailable. Workload shells belong to the separate sandbox image. Preserve
the driver-selected UID and writable runtime/log mounts when reproducing a
supervisor startup failure.

A `ConfigurationInvalid` readiness condition means startup admission rejected
the image/effective policy or provider configuration. The supervisor remains
alive while the workload stays unstarted. Inspect `openshell sandbox get` and
repair the desired configuration with a complete policy replacement or provider
change; do not treat a healthy container as proof that the workload is ready.
If the 300-second provisioning repair window expires, the gateway records
`ProvisioningTimedOut` and stops workload and supervisor compute. Inspect
`provisioning` in sandbox JSON and TUI NOTES to distinguish cleanup pending from
complete. Repairing configuration after expiry does not restart compute: wait
for cleanup, then explicitly use `sandbox start`. Repeated rejected reports do
not refresh the deadline, and the CLI wait timeout does not control it.
See [policy validation and repair](https://docs.nvidia.com/openshell/latest/sandboxes/policies.md).
The isolated supervisor requests image-policy discovery through the authenticated
sandbox boundary before admission. The workload boundary can remain alive without
launching the workload while configuration is repaired. An unavailable boundary
fails discovery within its control-request deadline. Permanent
gateway errors and exhausted transient retries terminate startup; inspect those
errors as connectivity, authorization, or lifecycle failures.

### Step 4: Check Docker-Backed Gateways

```bash
docker info
docker ps --filter name=openshell
docker logs <container> --tail=200
docker run --rm --entrypoint /openshell-sandbox "${OPENSHELL_SANDBOX_RUNTIME_IMAGE:-ghcr.io/nvidia/openshell/sandbox:latest}" --version
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
- Sandbox fails before readiness with an identity-resolution error: inspect the image's OCI `USER` and matching `/etc/passwd` and `/etc/group` entries, or explicitly set both process identity fields in policy. Numeric workload identities `1` through `4294967294` are accepted; root, the invalid identity sentinel, and missing identities are rejected.
- Sandbox fails before readiness with an OCI workspace validation error: inspect the image's `WorkingDir` using the immutable image ID reported by the gateway. Empty, `/`, and explicit `/sandbox` use the managed `/sandbox` compatibility workspace. Any other workdir must be an absolute normalized directory with no symlink components; the final policy UID, primary GID, and supplementary groups must pass the kernel's effective traverse/write checks, including POSIX ACL and LSM decisions. OpenShell does not create, chown, or chmod a non-default image workdir.
- Docker also rejects an image `VOLUME` that covers the workdir or one of its parents because the runtime would mask the immutable path before validation. Move the `VOLUME` below the workspace or remove the declaration.
- A workdir rejected as a special filesystem or OpenShell control-path collision cannot be made valid with permissions. Move the image workdir away from kernel-backed mounts and the concrete supervisor, TLS, token, runtime, and socket paths named in the error.
- Local Docker gateway setup cannot copy `openshell-sandbox` after exporting a supervisor image: the sandbox runtime and supervisor are separate artifacts. The runtime image must provide `/openshell-sandbox`; the supervisor image provides `/openshell-supervisor`.
- Docker driver cannot initialize because it cannot find `openshell-sandbox`: verify the sibling binary next to `openshell-gateway`, or that the configured `sandbox_runtime_image` contains `/openshell-sandbox`.
- Sandbox never registers: check gateway logs and the supervisor's gateway endpoint.
- Calls to an external tool server fail while the sandbox is Ready: inspect `Tool server connections` in `openshell sandbox get <name>`. For configured MCP-over-HTTP endpoints, JSON output exposes each address together with `last_result` and `last_reported_at` in `endpoint_statuses`. Select the endpoint by host, path, and ports, then check the reported failure boundary. `last_reported_at` records gateway acceptance time and can advance when retained evidence is accepted after a reset. Results do not expire or prove current availability; `HttpResponseReceived` can still contain a tool error. If several paths share a host and port, a failure before the path is known remains in logs. Verify the actual operation when current tool availability matters.
- On Docker Desktop, repeated `Policy fetch failed after 5 attempts` messages
  can mean host networking is disabled. Enable host networking in Docker
  Desktop, ensure Enhanced Container Isolation is disabled, and verify the
  gateway's primary endpoint is reachable from a host-networked container.
- Sandbox runtime image exits before printing `openshell-sandbox --version`: verify the configured image contains a static executable at `/openshell-sandbox`.
- A sandbox with explicit `protocol: tcp` endpoints fails before workload readiness: confirm the selected isolation backend advertises TCP mediation, then inspect the sandbox and supervisor logs for protected-channel setup or listener failures. A driver that cannot supply the required outer egress fence and authenticated runtime channel must reject the policy before starting the agent.
- Supervisor runtime validation fails: verify `supervisor_image` contains an `/openshell-supervisor` executable from the same release as the sandbox runtime, and that the dynamic loader and shared libraries it links against are available inside that image. `docker run --rm --network none --entrypoint /openshell-supervisor <supervisor_image> --version` should print that release; a `no such file or directory` error for a binary that exists means the loader or a library is missing. The supervisor runs from its own image and does not need to be static; only `/openshell-sandbox` must be.
- The sandbox fails its enforcement probe: inspect the sandbox log for the exact nested seccomp user-notification, task-memory, Landlock, loopback DNS, or socket-injection check that failed. A runtime may return `ENOSYS` for `process_vm_readv` and `process_vm_writev` while satisfying the production parent-to-workload-child task-memory probe through `/proc/<pid>/mem`; only failure of both backends is fatal. Do not add capabilities or switch to an unconfined seccomp profile; use a runtime whose default profile permits the unprivileged probe.
- A GPU sandbox fails because Docker reports no discovered NVIDIA CDI devices: verify `.DiscoveredDevices` contains entries such as `nvidia.com/gpu=all`, verify `/etc/cdi` or `/var/run/cdi` contains a generated NVIDIA spec, and check that `nvidia-cdi-refresh.service` and `nvidia-cdi-refresh.path` from NVIDIA Container Toolkit are enabled and healthy. The service is a one-shot unit, so `inactive (dead)` can be normal after a successful run; use `systemctl status` and `journalctl` to distinguish success from a skipped or failed refresh. Restart `nvidia-cdi-refresh.service` to regenerate missing or stale CDI specs, then restart or reload Docker and re-check `docker info`.

During a graceful gateway restart, Docker, Podman, and VM sandboxes with
running intent should stop before the gateway exits and restart after it
returns. Check for `Stopped sandbox during gateway shutdown` and `Started
sandbox during gateway startup` in gateway logs. A sandbox explicitly stopped
through the CLI remains stopped. Kubernetes sandboxes are cluster-owned and do
not follow this local gateway lifecycle. Internal and external drivers follow
the same rule: `GetCapabilities.gateway_manages_lifecycle` must be true for the
gateway to run shutdown and startup sweeps.

The gateway also drains supervisor-session ownership cleanup before exiting.
If shutdown reports `Gateway supervisor session cleanup incomplete`, inspect
the associated persistence errors: a stopped supervisor's owner record may
remain until its lease expires and temporarily block reconnection. Successful
compute stop alone does not confirm that session cleanup finished.

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
- Sandbox fails before readiness with an identity-resolution error: inspect the image's OCI `USER` and matching `/etc/passwd` and `/etc/group` entries, or explicitly set both process identity fields in policy. Numeric workload identities `1` through `4294967294` are accepted; root, the invalid identity sentinel, and missing identities are rejected.
- Supervisor cannot connect: check its gateway endpoint and gateway logs.
- Inspect both Podman containers for the sandbox: the `sandbox` isolation role
  must have network mode `none`; the `supervisor` role owns the gateway session
  and egress. Both run non-root with all capabilities dropped. Check the private
  channel volume and shared user-namespace mapping if authentication fails.
- If a sandbox fails before readiness, inspect its unprivileged enforcement
  probe and the companion supervisor's private health check. Do not add
  capabilities, attach a workload network, or disable the runtime seccomp
  profile. There is no sandbox nftables or nested-network setup to repair.
- On Linux, verify that the host-networked Podman supervisor can reach the
  gateway's primary loopback endpoint. On macOS, verify Podman Machine's
  host-loopback forwarding or configure an explicit `grpc_endpoint`.

When `userns` is configured (e.g. `userns = "auto"` or `userns = "keep-id"`):

- Sandbox runtime delivery uses bind-mount fallback instead of image volumes because
  overlay mounts do not support `idmapped` mounts. The supervisor binary is
  extracted from the sandbox runtime image and cached at
  `$XDG_DATA_HOME/openshell/podman-supervisor/` (typically
  `~/.local/share/openshell/podman-supervisor/`).
- Stale cache: if the sandbox runtime image is updated but the cached binary is not
  refreshed, sandbox creation may fail with an ELF validation error or version
  mismatch. Remove the cache directory and retry.
- `auto` mode requires subuid/subgid ranges for the current user in
  `/etc/subuid` and `/etc/subgid`. If missing, Podman returns a user-namespace
  mapping error at container creation.
- `private` mode requires explicit `uidmap` and `gidmap` arrays in the TOML
  config. Without both, the gateway rejects the config at startup.
  Rootless Podman uses intermediate IDs (e.g. `uidmap = ["0:0:1", "1:1:65535"]`);
  rootful Podman uses absolute host IDs (e.g. `uidmap = ["0:1000:1", "1:100000:65536"]`).
- `nomap` (without hyphen) is accepted as input but canonicalized to `no-map`
  for Podman's API.
- A workload remains in `stopping` until Podman resorts to `SIGKILL`: inspect
  supervisor logs for `failed to signal entrypoint process group`. The
  supervisor must retain `CAP_KILL` so its root process can forward `SIGTERM`
  to a workload that runs as the sandbox user.

### Step 6: Check Kubernetes Helm Gateways

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
mentioning `server.credentialDrivers` means the values selected multiple
external credential backends.

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
the right trust anchor.  Only override this if you intentionally mount a
separate client CA via `server.tls.clientCaSecretName`.  Verify the mounted
client CA matches the CA that signed the client certificate:

```bash
kubectl -n openshell get statefulset openshell -o jsonpath='{.spec.template.spec.volumes[?(@.name=="tls-client-ca")]}' | jq .
# Should show items filter for ca.crt from openshell-server-tls
```

If `server.providerTokenGrants.spiffe.enabled=true`, the gateway should still
render `[openshell.gateway.gateway_jwt]` and mount the `sandbox-jwt` Secret.
SPIRE is used by both the gateway and sandbox supervisors for dynamic provider
token grants. The gateway pod must mount the `spiffe-workload-api` CSI volume
and set `OPENSHELL_GATEWAY_SPIFFE_WORKLOAD_API_SOCKET`; supervisor Pods must
receive the matching Workload API socket from the Kubernetes driver config.
The gateway verifies supervisor JWT-SVIDs from JWT bundles fetched through this
Workload API socket, not from the SPIRE OIDC discovery endpoint.
Verify that SPIRE is installed, the CSI driver is available, and the Kubernetes
driver config includes `provider_spiffe_workload_api_socket_path`:

```bash
helm -n openshell get values openshell | grep -E 'providerTokenGrants|workloadApiSocketPath'
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

Check the image references currently used by the gateway deployment:

```bash
GATEWAY_DEPLOYMENT="$(kubectl -n openshell get deployment openshell >/dev/null 2>&1 && echo deployment/openshell || echo statefulset/openshell)"
kubectl -n openshell get "${GATEWAY_DEPLOYMENT}" -o jsonpath="{.spec.template.spec.containers[*].image}{\"\n\"}{.spec.template.spec.containers[*].env[?(@.name==\"OPENSHELL_SUPERVISOR_IMAGE\")].value}{\"\n\"}"
helm -n openshell get values openshell | grep -E 'repository|tag|supervisorImage|workload'
```

The gateway, sandbox, and supervisor images should use the same release tag. A stale runtime image can make sandbox behavior lag behind gateway policy or protocol changes.

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

```bash
helm -n openshell get values openshell | grep -A3 sandboxServiceAccount
kubectl -n <sandbox-namespace> get serviceaccount openshell-sandbox
kubectl -n openshell get configmap openshell-config -o jsonpath='{.data.gateway\.toml}'
kubectl -n <sandbox-namespace> get sandbox <sandbox-name> -o jsonpath='{.spec.template.spec.serviceAccountName}{"\n"}'
```

The Kubernetes driver creates a sandbox workload Pod and a separate, directly
managed supervisor Pod. Helm must render
`network_policy_enforced = true`. This is an explicit operator assertion that
the cluster CNI enforces Kubernetes NetworkPolicy; the Kubernetes API cannot
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

#### Corporate upstream proxy

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

### Step 7: Check VM-Backed Gateways

Use the VM driver logs and host diagnostics available in the user's environment. Verify:

- The VM driver process is running and reachable by the gateway.
- The runtime rootfs exists and matches the expected architecture.
- `mke2fs` or `mkfs.ext4` and `debugfs` from e2fsprogs are installed; explicit
  `sandbox_uid`/`sandbox_gid` does not remove this prerequisite.
- A persisted overlay identity error is resolved from its owner marker, overlay
  upper layer, prepared rootfs, explicit config, or current image. Do not assign
  `10001:10001` unless the persisted state reports that legacy identity.
- Host virtualization support is enabled.
- The sandbox supervisor can establish its authenticated gateway session.

Then run:

```bash
openshell status
openshell logs <sandbox-name>
```

#### Corporate upstream proxy

When VM sandbox egress routes through a corporate HTTP forward proxy, the
operator-owned settings live under `[openshell.drivers.vm]` and the gateway
forwards them to the `openshell-driver-vm` subprocess as `--upstream-proxy`,
`--upstream-no-proxy`, `--upstream-proxy-auth-file`,
`--upstream-proxy-auth-allow-insecure`,
`--upstream-proxy-connect-by-hostname`, and `--upstream-proxy-ca-bundle`. Both the gateway and
the driver validate them at startup, so any present-but-invalid value fails
closed with an error naming the key rather than reverting to a direct dial.
Confirm the configuration and the resulting driver argv first:

```bash
grep -A20 '^\[openshell.drivers.vm\]' <gateway.toml> | grep -E 'https_proxy|no_proxy|proxy_auth_file|proxy_auth_allow_insecure|proxy_connect_by_hostname|proxy_ca_bundle'
ps -o args= -p "$(pgrep -f openshell-driver-vm | head -n1)" | tr ' ' '\n' | grep -A1 -- '--upstream-proxy\|--upstream-no-proxy'
```

Both libkrun and QEMU guests are NIC-less. Proxy settings, credentials, and
private CA material stay with the host `openshell-supervisor`. For a proxy on
the gateway host, use `http://host.openshell.internal:<port>`; the supervisor
normalizes that name to host loopback. Inspect `supervisor.log` and
`supervisor.err.log` under the sandbox state directory for connection or
credential failures.

## Common Failure Patterns

| Symptom | Likely cause | Check |
|---|---|---|
| `openshell status` fails | Gateway endpoint unreachable or auth mismatch | `openshell gateway info`, gateway logs |
| `BatchSpanProcessor.ExportError` repeatedly reports connection refused on `127.0.0.1:4317` | The local gateway started with OTLP configured but the collector forwarding task later stopped, or the config was created manually | Restart `gateway:docker`, `gateway:podman`, or `gateway:vm` so it re-detects the listener; inspect the generated `gateway.toml` for `[openshell.gateway.otlp]` |
| Gateway starts but sandbox create fails | Compute driver cannot reach runtime | Docker/Podman/Kubernetes/VM driver logs |
| Docker or Podman sandbox never registers | Wrong gateway endpoint, unavailable host networking, or supervisor startup failure | Gateway logs and supervisor container logs |
| CPU-only VM startup reports that read-only `/proc` cannot be removed | Older supervisors can infer GPU requirements from host devices | Check gateway, VM driver, and bundled supervisor versions; use matching updated artifacts. CPU-only VMs do not require read-write `/proc`. |
| Docker GPU sandbox fails before startup | NVIDIA CDI specs are missing or Docker has not discovered them | `docker info --format '{{json .DiscoveredDevices}}'`, `/etc/cdi`, `/var/run/cdi`, `nvidia-cdi-refresh.service` |
| Kubernetes gateway pod pending | PVC unbound, taint, selector, or insufficient resources | `kubectl -n openshell describe pod <pod>` |
| Kubernetes sandbox pod stuck pending, workspace PVC unbound | Cluster has no default `StorageClass` and OpenShell does not set `storageClassName` on the workspace PVC (clusters with a default `StorageClass` bind fine without it) | `kubectl -n openshell describe pvc`; set `server.workspaceStorageClass` (gateway config `workspace_storage_class`) to a valid `StorageClass` |
| Kubernetes gateway pod crash loops | Missing secret, bad DB URL, bad TLS config | `kubectl -n openshell logs deployment/openshell -c openshell-gateway` or `kubectl -n openshell logs statefulset/openshell -c openshell-gateway` |
| OpenShift gateway pod fails to start with an SCC/`runAsUser` error (e.g. `unable to validate against any security context constraint`) | Chart's default `podSecurityContext`/`securityContext` hardcodes `runAsUser`/`fsGroup`, which the restricted-v2 SCC rejects; it must instead inject the namespace-assigned UID/GID range | `oc -n openshell describe pod <pod>`; deploy with `podSecurityContext: null` and clear `securityContext.runAsUser` (see `deploy/helm/openshell/ci/values-openshift-scc.yaml`) |
| OpenShift sandbox pod fails to start (`unable to validate against any security context constraint`) | The `openshell-sandbox` service account lacks the privileged SCC it needs | `oc adm policy add-scc-to-user privileged -z openshell-sandbox -n openshell`; remove with `remove-scc-from-user` when done |
| OpenShift self-hosted Vault/OpenBao credential store pod never schedules (waits time out with `no matching resources found`) | The store's Helm chart pins `runAsUser`/`fsGroup`/seccomp, which restricted-v2 rejects, so the StatefulSet controller never creates the pod | Deploy the store's chart in its OpenShift mode (`--set global.openshift=true` for the OpenBao/Vault chart) so the namespace SCC assigns a compliant security context — no manual SCC grant needed |
| Vault credential driver returns HTTP 403 / `Vault Kubernetes auth denied the configured role` on provider create | Vault's `auth/kubernetes` method or the gateway login role is not provisioned, or the role is not bound to the gateway service account and namespace | In Vault: `bao auth enable kubernetes` and `bao write auth/kubernetes/config kubernetes_host=... kubernetes_ca_cert=@...`; ensure the login role's `bound_service_account_names`/`bound_service_account_namespaces` match the gateway SA and namespace and its policy grants the credential paths |
| CLI TLS error | Local mTLS bundle does not match server cert/CA | Check `~/.config/openshell/gateways/<name>/mtls/` |
| Edge or OIDC gateway returns `Unauthenticated` | Stored login expired, audience/scopes mismatch, or gateway auth configuration changed | `openshell gateway info`, `openshell gateway login <name>`, gateway auth logs |
| Gateway exits during OIDC initialization | Issuer is not HTTPS, discovery redirected, metadata used a non-JSON media type or exceeded its size limit, or `jwks_uri` uses an untrusted origin | Use an HTTPS issuer; mount a private CA with `server.oidc.caConfigMapName`; keep JWKS on the issuer origin or explicitly add its HTTPS origin to `server.oidc.jwksAllowedOrigins`. Numeric-loopback HTTP is development-only and also requires `server.oidc.dangerouslyAllowInsecureHttp=true` |
| Gateway fails before serving health after enabling an interceptor | Interceptor endpoint unavailable or manifest/binding validation failed | Gateway and interceptor logs; interceptor socket; `binding_policy`, phases, and failure policy |
| Authenticated interceptor or middleware rejects gateway calls | Private CA or hostname mismatch, expected audience or issuer mismatch, stale/unknown `kid`, or malformed extension token | `tls_ca_cert_path`, registration `audience`, service verifier config and logs; fetch well-known metadata only through the already-trusted gateway TLS endpoint |
| Provider profiles disappear after enabling an interceptor catalog | `provider_profile_sources` selected only an authoritative interceptor or returned invalid/duplicate IDs | Inspect source list and interceptor `Describe`/catalog logs; include `user` when composition with imported profiles is intended |
| `provider list-profiles` is empty on a new gateway | Profiles are import-only and nothing has been imported | Import with `openshell provider profile import --from providers --global`; an empty catalog is a valid ready state, not a failure |
| Sandbox create or provider attach fails naming a missing profile | The provider's profile was never imported, was deleted, or lives at another scope | Import it at the scope the provider uses; the error names the profile ID and the command |
| Gateway fails after registering supervisor middleware | Service unavailable, invalid manifest, duplicate binding, reserved name, or invalid payload/timeout limit | Middleware service and gateway logs; `[[openshell.supervisor.middleware]]`; `Describe` response |
| Policy update rejects `network_middlewares` | Unknown middleware name, implementation-owned config invalid, duplicate order, broad/invalid host selector, or fail-closed coverage of `tls: skip` | Policy error, gateway logs, middleware `ValidateConfig`, selector and order fields |
| Gateway or extension rejects its peer before serving health | Missing peer metadata, incompatible protocol major, or unmet `required_capabilities` | Gateway and extension startup logs; compare `PeerMetadata`; legacy-to-current migration requires a coordinated gateway and extension outage |
| Policy mutation returns `FAILED_PRECONDITION` for endpoint ambiguity | Equally specific effective endpoint selectors disagree on connection or request-processing metadata | CLI error, base and provider-composed policy, affected profile attachments; confirm no new revision was stored |
| Supervisor enters policy quarantine | A runtime candidate failed validation while `policy_validation_failure_mode = "fail_closed"` | Sandbox OCSF config/finding events, validation rationale, active generation, `previous_policy_active` |
| Custom compute driver is unavailable | Driver process/socket missing, inaccessible, or selected name does not match its endpoint/config key | Socket ownership/mode, driver service logs, gateway `GetCapabilities` logs |
| Sandbox remains `Stopping` or `Starting` | Driver stop/start failed, retained resource is missing, or a fresh supervisor has not connected | Gateway and driver logs; `docker inspect`, `podman inspect`, Agent Sandbox status/PVC, or VM state marker and launcher process |
| Image pull failure | Gateway or sandbox image cannot be pulled | Runtime events and image pull credentials |
| Gateway API resources fail with `the server could not find the requested resource` | Optional Gateway API resources were applied without Envoy Gateway CRDs | Install Envoy Gateway and enable `grpcRoute` before applying the optional ingress resources |
| HTTPS ingress (`grpcRoute.gateway.listener.protocol=HTTPS`) connection resets or TLS handshake hangs | Envoy terminates TLS but the gateway pod still expects TLS, so the plaintext backend hop fails | Set `server.disableTls=true` so Envoy forwards plaintext to the pod; verify the listener `certificateRefs` Secret exists in the release namespace and `openshell status` over `https://<host>` |
| HTTPS ingress returns `Unauthenticated` after connecting | TLS terminates at Envoy, so the gateway never sees a client cert; no OIDC issuer is configured for identity | Configure `server.oidc.issuer` and register with `openshell gateway add https://<host> --oidc-issuer <url>`, or set `server.auth.allowUnauthenticatedUsers=true` for a trusted-proxy/dev cluster |
| External server `Certificate` never becomes Ready with `certManager.serverIssuerRef` set | ACME issuer rejected internal-only SANs, a loopback IP, or a `commonName` absent from the SANs | `kubectl -n openshell describe certificate openshell-server-external`; confirm `certManager.serverDnsNames` lists only real, externally-resolvable hostnames |
| Sandbox supervisors fail TLS handshake with `UnknownCA` after configuring `certManager.serverIssuerRef` | `server.grpcEndpoint` is set to the external hostname, forcing supervisors to receive the ACME cert (via SNI) which they can't verify against chart CA | Remove `server.grpcEndpoint` or set it to the internal service name; supervisors should connect via internal service name to receive the internal cert |
| Browser `ERR_BAD_SSL_CLIENT_AUTH_CERT` or gateway logs show client cert verification when OIDC or direct HTTPS is expected | Listener client-CA verification still enabled (`clientCaSecretName` unset or `client_ca_path` in ConfigMap) | Set `server.tls.clientCaSecretName=""`, upgrade chart, confirm ConfigMap omits `client_ca_path` |

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

## Package Configuration Preflight

For a Debian, Ubuntu, or Snap gateway that stops before certificate generation or
daemon startup, validate the selected configuration without starting the service:

```shell
openshell-gateway config preflight [--path PATH | -- GATEWAY_ARGS...]
```

Without a path, preflight validates a nonempty `OPENSHELL_GATEWAY_CONFIG` or an
auto-discovered XDG config; no config succeeds. An explicit missing path, legacy
schema-v1 file, malformed TOML, symlink, or nonregular file fails before gateway
startup. It also applies read-only effective-config checks for driver selection
and configuration, sockets, rate limits, TLS, interceptors, and supervisor
middleware. If the file omits the selector, preflight validates configured tables
for auto-detectable drivers without running socket or process-based detection
probes. Arguments after `--` validate the effective daemon invocation,
including its command-line overrides. Preflight preserves every failed file. Do
not advise users to delete or rewrite it automatically; back it up and follow the
manual schema-v2 migration in the Gateway Configuration reference.
