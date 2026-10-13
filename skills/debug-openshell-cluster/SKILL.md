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

For local evaluation only, TLS may be disabled and the gateway can be reached through `http://127.0.0.1:<port>`.

## Prerequisites

- The `openshell` CLI must be available for endpoint checks.
- Know the active gateway name and endpoint, or be able to inspect local gateway metadata.
- Know the compute platform: Docker, Podman, Kubernetes, VM, or an out-of-tree driver.
- For Kubernetes: `kubectl` must target the cluster that hosts OpenShell and Helm version 3 or later must be available.
- For Docker or Podman: the runtime socket must be reachable from the gateway host.

This skill and its references give the diagnostic commands for each platform and for `openshell-gateway`. Run `openshell agent context` only when you need an `openshell` command they do not show; it lists every `openshell` command and flag of the installed CLI, and nothing for `openshell-gateway`, `docker`, `podman`, `kubectl`, `helm`, or `systemctl`. `openshell <command> --help` explains what an `openshell` command's flags do. Use the published [installation guide](https://docs.nvidia.com/openshell/latest/about/installation.md), [compute-driver reference](https://docs.nvidia.com/openshell/latest/how-it-works/sandboxes/runtimes), [gateway configuration reference](https://docs.nvidia.com/openshell/latest/how-it-works/gateways/configuration), and [Kubernetes setup guide](https://docs.nvidia.com/openshell/latest/kubernetes/setup.md) as the authority for deployment and configuration behavior.

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
- TLS/certificate errors: the endpoint scheme or trust chain is wrong, a CLI mTLS bundle does not match the gateway CA, a supervisor is missing the gateway CA, or TLS termination does not match the gateway listener. Workloads and supervisors should not contain a user TLS client certificate or private key.
- Fresh snap installations use `openshell.user-gateway`; upgraded installations retain their system-owned state through `openshell.system-gateway`. Existing HTTPS registrations continue to work after the service rename. Follow the published snap installation steps to enroll a new user, replace an old HTTP registration, or change modes safely through the `disable` maintenance state. If `gateway-mode=disable`, no local snap gateway is expected to run.
- `Unauthenticated` from an edge or OIDC gateway: refresh stored credentials with `openshell gateway login [name]`, then retry. Use `gateway logout` only when intentionally clearing local credentials.
- Operator credential retrieval requires direct gateway mTLS, `[openshell.gateway.mtls_auth] operator_enabled = true`, and a verified certificate with exact `OU=operator`. OIDC admin roles and forwarded certificate headers do not grant access. Do not combine the operator certificate with an `Authorization` header. Enabling this role grants gateway-wide administration; never repair a denial by issuing operator certificates to ordinary users. See the published gateway authentication and provider references.
- A direct development endpoint with a private or self-signed certificate can be isolated with `--gateway-endpoint <url> --gateway-insecure`; do not persist or recommend insecure verification for shared gateways.

### Step 2: Identify the Compute Platform

Use gateway metadata, deployment values, or the user's setup notes to identify the driver, then read only the matching reference. When a task needs several references, such as a platform reference and [references/gateway-startup.md](references/gateway-startup.md), read them in the same step with one call per file; printed together, they are too large for one tool result.

| Platform | Primary checks | Reference |
|---|---|---|
| Docker | Gateway process logs, Docker daemon health, sandbox containers, image pulls, GPU CDI devices. | [references/docker.md](references/docker.md) |
| Podman | Podman socket, rootless networking, user namespaces, sandbox containers, image pulls. | [references/podman.md](references/podman.md) |
| Kubernetes | Helm release, gateway workload, service, secrets, sandbox pods, events. Multi-replica relay, TLS, and certificates. | [references/kubernetes.md](references/kubernetes.md), [references/kubernetes-tls-and-replicas.md](references/kubernetes-tls-and-replicas.md) |
| OpenShift | Same as Kubernetes, plus SecurityContextConstraints (SCCs) and, for external access, an OpenShift `Route`. Detect OpenShift by the presence of the `route.openshift.io` API group (`oc api-resources --api-group=route.openshift.io`). | [references/kubernetes.md](references/kubernetes.md), [references/kubernetes-tls-and-replicas.md](references/kubernetes-tls-and-replicas.md) |
| VM | VM driver logs, rootfs availability, host tools, host virtualization support. | [references/vm.md](references/vm.md) |
| Extension | External driver process, Unix socket ownership/mode, configured driver name, capability handshake, gateway logs. | [references/gateway-startup.md](references/gateway-startup.md) |

### Step 3: Check Gateway Startup Dependencies

When the gateway fails before its listener is ready, or a configured dependency misbehaves, read [references/gateway-startup.md](references/gateway-startup.md). It covers compute driver registration and selection, gateway configuration schema, credential drivers (Kubernetes Secrets, Vault), gateway interceptors, policy validation failure modes, supervisor images, `ConfigurationInvalid` repair, and sandbox behavior across gateway restarts. For supervisor middleware, read [references/supervisor-middleware.md](references/supervisor-middleware.md).

### Step 4: Check the Compute Platform

Follow the platform reference from Step 2. Each lists the platform's diagnostic commands, common findings, and corporate upstream proxy checks.

## Common Failure Patterns

Platform-independent symptoms. Kubernetes and OpenShift symptoms are in [references/kubernetes.md](references/kubernetes.md).

| Symptom | Likely cause | Check |
|---|---|---|
| `openshell status` fails | Gateway endpoint unreachable or auth mismatch | `openshell gateway info`, gateway logs |
| Gateway OCSF JSONL stops growing, has gaps, or is rejected by a SIEM | File errors, queue pressure, shipper falling behind retention, or a schema mismatch | Inspect gateway warnings and `openshell_ocsf_log_*` metrics; check `[openshell.gateway.ocsf_log]`, `schema_version`, directory permissions, free space, per-replica paths, and shipper rotation checkpoints. See the published [gateway configuration reference](https://docs.nvidia.com/openshell/latest/how-it-works/gateways/configuration). |
| `BatchSpanProcessor.ExportError` repeatedly reports connection refused on `127.0.0.1:4317` | The local gateway started with OTLP configured but the collector forwarding task later stopped, or the config was created manually | Restart `gateway:docker`, `gateway:podman`, or `gateway:vm` so it re-detects the listener; inspect the generated `gateway.toml` for `[openshell.gateway.otlp]` |
| Gateway starts but sandbox create fails | Compute driver cannot reach runtime | Docker/Podman/Kubernetes/VM driver logs |
| Docker or Podman sandbox never registers | Wrong gateway endpoint, unavailable host networking, or supervisor startup failure | Gateway logs and supervisor container logs |
| CPU-only VM startup reports that read-only `/proc` cannot be removed | Older supervisors can infer GPU requirements from host devices | Check gateway, VM driver, and bundled supervisor versions; use matching updated artifacts. CPU-only VMs do not require read-write `/proc`. |
| Docker GPU sandbox fails before startup | NVIDIA CDI specs are missing or Docker has not discovered them | `docker info --format '{{json .DiscoveredDevices}}'`, `/etc/cdi`, `/var/run/cdi`, `nvidia-cdi-refresh.service` |
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

For a Debian, Ubuntu, or snap gateway that stops before certificate generation or
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
