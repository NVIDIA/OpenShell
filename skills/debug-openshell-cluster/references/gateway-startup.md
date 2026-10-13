# Gateway startup dependencies

Inspect gateway logs for failures in dependencies initialized before the listener becomes ready, before debugging the compute platform.

## Compute driver registration

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

See the [compute driver reference](https://docs.nvidia.com/openshell/latest/how-it-works/sandboxes/runtimes)
for selective-build options and external-driver configuration.

## Startup checks

Before debugging the compute platform, inspect gateway logs for failures in dependencies initialized before the listener becomes ready.

The gateway container uses a Distroless Debian runtime. For OS-library
vulnerability findings, check the deployed image digest and package version;
deploy a rebuilt gateway image with the patched base. Updating the gateway
binary alone does not update the libraries supplied by its container image.

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
Empty, invalid, comma-delimited, or conflicting values fail startup. The
WebSocket tunnel for edge-proxy CLI access is off unless
`enable_websocket_tunnel = true` (`server.enableWebsocketTunnel` in Helm). Homebrew
and RPM package startup migrates only exact package-generated v1 defaults. If
an upgraded package still reports an unsupported version, inspect the active prefix or `~/.config/openshell/gateway.toml`; an edited v1 file must
follow the published schema-v2 migration steps and must not be overwritten.
The supervisor gateway CA is the exception to driver ownership: configure
`guest_tls_ca` under `[openshell.gateway]`, and the gateway injects it only into
the selected local driver. Remove the retired `guest_tls_cert` and
`guest_tls_key` fields. TLS-enabled Docker, Podman, and VM drivers fail startup
when neither that CA nor the package-managed local CA is available. Kubernetes
projects only the gateway CA from a Secret into supervisor Pods; supervisors
authenticate gateway RPCs with sandbox bearer tokens.

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
[supervisor middleware troubleshooting reference](supervisor-middleware.md)
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
For custom builds using `SUPERVISOR_BASE_IMAGE`, check the selected base's GNU
runtime libraries, CA certificates, and inherited user and working directory.
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
See [policy validation and repair](https://docs.nvidia.com/openshell/latest/how-it-works/policies/overview).
The isolated supervisor requests image-policy discovery through the authenticated
sandbox boundary before admission. The workload boundary can remain alive without
launching the workload while configuration is repaired. An unavailable boundary
fails discovery within its control-request deadline. Permanent
gateway errors and exhausted transient retries terminate startup; inspect those
errors as connectivity, authorization, or lifecycle failures.

## Sandboxes across gateway restarts

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

For a sandbox with `--restart-policy on-failure` or `always`, inspect
`openshell sandbox get <name>` for the policy, exit code, restart count, and
next restart time. `Starting` can mean the gateway is waiting for backoff or
for a replacement supervisor. Check gateway logs for stop or start errors if
the deadline passes without a transition to `Ready`. Docker, Podman,
Kubernetes, and VM native restart policies remain disabled; the gateway owns
the replacement.
