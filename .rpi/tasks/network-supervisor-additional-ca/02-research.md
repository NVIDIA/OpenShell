---
rpi_task: network-supervisor-additional-ca
workflow: rpi
phase: research
document_status: ready
updated: 2026-09-10T22:18:30Z
---

# Research: additional CA materials for the network supervisor

## Summary

OpenShell has one shared network-supervisor implementation, but it does not currently have a shared gateway configuration field for additional destination trust roots. The supervisor's upstream TLS client is constructed in `openshell-supervisor-network` during sandbox startup. It starts with the system/bundled trust roots and can currently receive an extra PEM bundle only through the corporate upstream-proxy option `--upstream-proxy-ca-bundle`.

That existing option is not a solution for this request: it is rejected unless an upstream proxy is configured, is exposed only by the Podman driver today, and is not propagated by Docker, Kubernetes, or VM. The common path after supervisor launch is suitable for uniform trust behavior, but each driver currently has a different way to launch or stage the supervisor. The design must therefore separate the requested CA setting from proxy configuration and define a shared transport contract that works for all four in-tree compute drivers.

The repository evidence supports a startup-oriented, additive trust model, but does not select the eventual configuration section, material representation, propagation mechanism, or reload behavior. Those choices remain for Design.

## 1. Gateway configuration model and possible shared locations

### Current schema

The gateway TOML is rooted at `[openshell]`. `ConfigFile` and `OpenShellRoot` define gateway, supervisor, driver, and credential-driver sections in `crates/openshell-server/src/config_file.rs:38-80`. `[openshell.gateway]` is represented by `GatewayFileSection` (`config_file.rs:83-190`) and contains gateway-wide listeners, logging, sandbox defaults, service routing, gateway TLS/auth, and related settings. The currently defined `[openshell.supervisor]` section (`config_file.rs:209-247`) contains static operator-run supervisor middleware registrations; it is not the network supervisor's runtime configuration.

All configuration tables use `serde(deny_unknown_fields)`. `load()` reads and deserializes the file, rejects unsupported schema versions and database secrets in the file, and returns a hard error for parse/I/O failures (`config_file.rs:373-416`). The configuration precedence is CLI, environment, TOML, then built-in defaults (`config_file.rs:1-24`; RFC 0003, `rfc/0003-gateway-configuration/README.md:25-42`).

Driver tables are intentionally raw TOML owned by each driver. `driver_table()` overlays only an explicit allowlist of shared gateway fields into `[openshell.drivers.<name>]` (`config_file.rs:419-526`). The allowlist currently covers images, host/network defaults, Kubernetes service-account values, and guest TLS paths; it does not include any network-supervisor CA setting. Tests cover inheritance, driver-local precedence, and prevention of unsupported keys leaking into a driver table (`config_file.rs:968-1112`).

### Related but distinct CA settings

`[openshell.gateway.tls]` configures the gateway listener and is not sandbox destination trust. `[[openshell.supervisor.middleware]]` has `tls_ca_cert_path`, but that path is for gateway/supervisor connections to a configured middleware service; `TryFrom<&MiddlewareServiceFileConfig>` reads and sanitizes that file into a middleware protobuf (`config_file.rs:249-318`). It does not feed the network supervisor's upstream destination root store.

Driver `guest_tls_ca` fields likewise authenticate the sandbox to the gateway and are distinct from CA roots used to verify arbitrary network destinations. The distinction is documented in the full gateway configuration example (`docs/reference/gateway-config.mdx:85-210`) and in the driver sections (`docs/reference/gateway-config.mdx:350-750`).

The Helm chart renders a gateway TOML ConfigMap and mounts it for gateway startup (`deploy/helm/openshell/templates/gateway-config.yaml:1-35`). It currently renders Kubernetes proxy settings in `[openshell.drivers.kubernetes]` but no general additional-CA setting (`gateway-config.yaml:127-167`). RFC 0003 explicitly makes hot reload out of scope and describes all file/env merging at startup (`rfc/0003-gateway-configuration/README.md:25-42`).

### Evidence-based implication

There is no existing shared field for this request. A field under `[openshell.gateway]` would be outside driver-specific sections and could participate in the existing gateway startup context, while a field under `[openshell.supervisor]` would be a new sibling concern alongside middleware. The current code does not decide between those locations; the placement and naming require an explicit design decision.

## 2. Network-supervisor TLS trust and data flow

### Shared supervisor entry point

`openshell-sandbox` is the common supervisor binary. Its CLI defines the current operator-owned corporate-proxy arguments, including `--upstream-proxy-ca-bundle` (`crates/openshell-sandbox/src/main.rs:180-245`). The parsed values are converted into `UpstreamProxyArgs` and passed to `run_sandbox` (`sandbox/src/main.rs:678-715`). When networking is enabled, `run_sandbox` calls the shared `openshell_supervisor_network::run::run_networking` initializer (`sandbox/src/lib.rs:528-551`).

The relevant common flow is:

```text
compute-driver launch configuration
        -> openshell-sandbox argv/filesystem
        -> UpstreamProxyArgs
        -> run_sandbox
        -> run_networking
        -> system/additional CA material
        -> upstream rustls ClientConfig
        -> shared network proxy and TLS connections
```

### Trust-store construction

In proxy network mode, `run_networking` generates an ephemeral OpenShell MITM CA, reads the system CA bundle, optionally reads the existing proxy CA bundle, writes sandbox trust files, and builds one upstream TLS client configuration (`crates/openshell-supervisor-network/src/run.rs:319-385`). The resulting `ProxyTlsState` stores that `ClientConfig` and reuses it for upstream TLS connections.

`build_upstream_client_config()` in `supervisor-network/src/l7/tls.rs:209-278` builds a rustls client with HTTP/1.1 ALPN and a `RootCertStore`. With the default `bundled-ca-roots` feature (`supervisor-network/Cargo.toml:55-56`; `openshell-sandbox/Cargo.toml:58-65`), Mozilla roots are loaded first and PEM certificates from the supplied bundle are overlaid. Thus the intended additive behavior is already represented in the shared helper. When compiled without that feature, the current implementation loads the native platform store and ignores the PEM argument because it assumes the native store contains operator-installed roots (`l7/tls.rs:240-258`). The resulting store must not be empty (`l7/tls.rs:260-264`).

`read_system_ca_bundle()` checks common locations and returns the first non-empty file, rather than merging every path (`l7/tls.rs:333-352`). The current default search paths are Debian/Ubuntu, RHEL/Fedora, openSUSE, and Alpine/macOS locations.

For a configured `proxy_ca_bundle`, `run_networking` validates and appends the file's PEM text to the system bundle before both writing the sandbox's combined `ca-bundle.pem` and constructing the upstream client (`run.rs:324-351`). The standalone `openshell-ca.pem` contains the generated MITM CA; the combined bundle contains the supplied system material plus the generated OpenShell CA (`l7/tls.rs:280-308`). Child-process environment helpers expose those paths through `NODE_EXTRA_CA_CERTS`, `DENO_CERT`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, and `GIT_SSL_CAINFO` (`crates/openshell-supervisor-process/src/child_env.rs:20-38`, with process/SSH use at `process.rs:1008-1012` and `ssh.rs:1169-1171`).

The upstream TLS handshake uses the shared config and preserves hostname verification (`l7/tls.rs:171-204`). A destination signed by a private CA succeeds only when that CA is present in the root store; a self-signed/private destination is not implicitly trusted merely because it is reachable.

### Existing proxy CA boundary

`UpstreamProxyArgs` documents `proxy_ca_bundle` as a PEM file used for an HTTPS corporate proxy and, for TLS-intercepting proxies, the sandbox bundle and upstream verification (`crates/openshell-supervisor-network/src/upstream_proxy.rs:318-357`). `read_proxy_ca_bundle()` reads UTF-8 PEM, requires at least one certificate block, and then requires at least one rustls-usable trust anchor (`upstream_proxy.rs:602-639`). It returns actionable errors naming the flag and path. `UpstreamProxyConfig::from_args()` rejects this auxiliary setting when no proxy URL is present and validates it for both HTTP and HTTPS proxies (`upstream_proxy.rs:386-438`, `500-519`).

This is a useful fail-closed validation pattern, but the current pairing rule makes the setting unsuitable as a general additional destination CA. It also means that the existing path is not exercised in direct-egress configurations.

### Scope of current TLS verification

The constructed client configuration is used for L7 proxy upstream re-encryption. Raw/direct paths and transparent TCP enforcement do not turn arbitrary destination TLS into a supervisor-verified TLS session; they forward the connection while applying their respective network policy. Any implementation must therefore state whether the requested additional roots apply to the shared L7 upstream client only, to generated sandbox process trust files as well, or to another path. The current code shows both the supervisor's upstream store and the child-process bundle as natural trust consumers, but does not establish a new scope.

## 3. Compute-driver launch and propagation matrix

The gateway creates a single `DriverStartupContext` containing the parsed config file, guest TLS paths, gateway port/TLS state, and endpoint overrides (`crates/openshell-server/src/compute/driver_config.rs:24-55`; constructed in `crates/openshell-server/src/lib.rs:584-609`). Built-in driver factories deserialize their own merged driver tables and apply runtime defaults (`compute/driver_config/builtin.rs:13-115`). The context currently carries no additional network-supervisor CA material.

| Driver/topology | How the common supervisor is started | Existing extra-CA/proxy propagation | Evidence |
|---|---|---|---|
| Docker | Host `openshell-sandbox` is bind-mounted; container entrypoint is the supervisor and command is only `--workdir <workspace>`. | No proxy or CA fields in `DockerComputeConfig`; binds include the supervisor and optional guest mTLS files, not a destination CA. | `crates/openshell-driver-docker/src/lib.rs:116-184`, `2605-2630`, `3019-3030` |
| Podman | Supervisor command is constructed in the container spec and the shared binary initializes networking. | Has driver-specific `proxy_ca_bundle`; validates it only alongside `https_proxy`, bind-mounts the host PEM read-only at `PROXY_CA_MOUNT_PATH`, and passes `--upstream-proxy-ca-bundle` (`container.rs:437-475`, `1066-1078`, `1300-1330`). | `crates/openshell-driver-podman/src/config.rs:190-210`, `320-417`; `container.rs:437-475`, `1300-1330` |
| Kubernetes combined | Side-loaded supervisor command replaces the agent command and receives proxy flags. | Kubernetes config has proxy URL/no-proxy/auth/hostname settings but no `proxy_ca_bundle`; no CA volume/flag is added. | `crates/openshell-driver-kubernetes/src/config.rs:327-340`; `driver.rs:2515-2573`, `2598-2634` |
| Kubernetes sidecar | Dedicated network sidecar runs `/openshell-sandbox --mode=network`; the network-init container only prepares rules. | Sidecar receives current proxy args and auth volume, but no proxy CA setting or CA volume; tests ensure proxy args reach network supervisors and not network-init/agent containers. | `crates/openshell-driver-kubernetes/src/driver.rs:2743-2810`, `2825-2835`, `7642-7708` |
| VM | `openshell-sandbox` is embedded/staged into the guest root filesystem and executed by the VM runtime. | `VmDriverConfig` contains guest mTLS paths but no upstream proxy or supervisor destination-CA field. Guest environment includes gateway identity, process specification, logging, and guest TLS paths; no additional CA is staged. | `crates/openshell-driver-vm/src/driver.rs:221-255`, `4470-4550`; `crates/openshell-driver-vm/src/rootfs.rs:1234-1237`; `crates/openshell-driver-vm/src/runtime.rs:885-910` |

After launch, the supervisor code is shared. Kubernetes sidecar process trust paths are transferred separately through `sidecar_control::BootstrapData`, but the existing `proxy_ca_cert_path` and `proxy_ca_bundle_path` fields are the generated OpenShell CA paths produced by `run_networking`, not operator-configured additional roots (`crates/openshell-sandbox/src/sidecar_control.rs:20-32`, `190-263`; `sandbox/src/lib.rs:555-590`).

The matrix shows why adding a field to one driver or reusing the Podman-only proxy field cannot satisfy the cross-driver requirement. Each driver must receive the same normalized trust material through a driver-appropriate staging mechanism, after which `run_networking` can remain driver-independent.

## 4. Existing validation, trust, and error patterns

### Configuration and certificate validation

The gateway configuration loader already has a certificate-file pattern for supervisor middleware: read the configured path during conversion, parse all PEM items, reject non-certificate blocks, reject empty bundles, and return errors naming the middleware and path (`config_file.rs:249-318`, `320-371`). It also sanitizes accepted certificates into canonical PEM rather than preserving arbitrary blocks.

The network supervisor's proxy CA path uses a related but later validation boundary: it validates the file when the supervisor starts, checks both PEM framing and usable X.509 trust anchors, and fails before proxy setup on unreadable/unusable material (`upstream_proxy.rs:611-632`; `run.rs:334-340`). The error strings avoid certificate contents and identify the operator-facing argument/path.

### Tests that provide reusable seams

- `supervisor-network/src/l7/tls.rs:390-495` tests CA generation, one/multiple PEM certificates, empty input, malformed PEM, mixed valid/invalid input, and generated CA output files.
- `supervisor-network/src/upstream_proxy.rs:1310-1390` tests missing files, empty/non-certificate input, and invalid DER for proxy CA bundles.
- `upstream_proxy.rs:2028-2135` composes a generated CA, a TLS server, and the upstream client to test successful hostname verification and rejection of a mismatched hostname.
- `openshell-server/src/config_file.rs:968-1112` tests shared gateway inheritance and driver-specific precedence/exclusion.
- `openshell-driver-podman/src/config.rs:706-744` and `container.rs:2150-2205` test current proxy-CA validation, bind mounts, supervisor argv, and omission when unset.
- `openshell-driver-kubernetes/src/driver.rs:7642-7708` verifies proxy arguments are injected only into network supervisors; it currently has no additional-CA assertion.
- `openshell-sandbox/src/sidecar_control.rs:683-718` tests generated CA-path bootstrap serialization.

There is no current shared configuration/propagation contract test covering Docker, Podman, Kubernetes combined/sidecar, and VM for one operator-configured destination CA. There is also no end-to-end test that starts each driver against a server signed by an operator-provided private CA.

## 5. Compatibility, security, and operational constraints

1. **Additive trust is already the intended default.** The default bundled-root build overlays supplied PEM onto Mozilla roots, and `run_networking` appends extra material to the system bundle. Unset configuration should preserve current system/public roots and generated OpenShell CA behavior.
2. **Fail closed for explicitly configured material.** An unreadable path, empty bundle, PEM without certificates, or PEM with no usable X.509 trust anchors must not silently become “no additional roots.” Existing proxy and middleware paths provide actionable error conventions.
3. **Preserve hostname verification.** Trusting a configured CA must not disable rustls server-name checks or accept arbitrary self-signed leaves without the configured root.
4. **Do not log certificate contents.** CA certificates are generally public material, but logs should identify a setting/path and validation result rather than emit PEM bytes. No real certificates or credentials belong in source control or task artifacts.
5. **The material must exist where the supervisor runs.** A gateway-host path is not automatically visible inside a Docker/Podman container, Kubernetes pod, or VM guest. The propagation contract must mount, copy, or otherwise stage the material for the supervisor in each driver topology. VM guest TLS paths are a separate staging mechanism and must not be conflated with destination trust.
6. **Operator and sandbox inputs must remain separated.** Existing proxy settings deliberately travel on supervisor argv rather than sandbox environment, preventing image `ENV` or sandbox template variables from changing the operator-owned egress boundary. Any new path should preserve that boundary.
7. **Lifecycle is startup-oriented today.** Gateway TOML is loaded at gateway startup; RFC 0003 explicitly excludes hot reload. The network supervisor builds its root store once during sandbox startup. Existing gateway TLS reload support does not imply network-supervisor CA reload support. Whether changes affect only newly created/restarted sandboxes or require a separate runtime reload is unresolved.
8. **Compilation feature behavior needs an explicit decision.** The default build uses `bundled-ca-roots`, where passed PEM is honored. The no-bundled-roots build currently ignores the PEM argument in favor of native roots, so any implementation claiming support across build variants must either preserve/document that behavior or change the shared helper deliberately.

## 6. Direct answers to the research questions

| Question | Current-state answer |
|---|---|
| Where is shared configuration parsed? | `ConfigFile`/`GatewayFileSection` in `openshell-server/src/config_file.rs`; `[openshell.supervisor]` currently means middleware registrations, and driver tables are raw/driver-owned. |
| Where is destination TLS trust built? | `run_networking` reads CA material and calls `l7::tls::build_upstream_client_config`; `ProxyTlsState` reuses the resulting client for upstream TLS. |
| How does data reach all drivers? | It does not today for a general additional CA. Docker and VM have no path; Podman has proxy-only path; Kubernetes has proxy args but no proxy CA path. All converge on `openshell-sandbox` after launch. |
| What happens for private/self-signed destinations? | They fail upstream certificate verification unless their CA is already in the supervisor's system/bundled roots or the existing proxy CA path is used. Hostname verification remains active. |
| Can roots be additive? | Yes in the default `bundled-ca-roots` path: Mozilla roots plus supplied/system PEM. The native-only feature path currently ignores the PEM argument. |
| What validation conventions exist? | Read at startup/config conversion, require certificate-only PEM and at least one usable X.509 anchor, report path/field, and fail closed. |
| What tests exist? | Shared root-store and TLS tests, proxy CA failure tests, config inheritance tests, Podman propagation tests, and Kubernetes network-supervisor placement tests; no all-driver contract test. |
| What documentation is implicated? | `docs/reference/gateway-config.mdx`, likely the driver reference for launch/staging details, Helm ConfigMap/values/templates, and a stable architecture overview such as `architecture/sandbox.md` after design is approved. |

## 7. Unresolved questions for Design

1. **Placement and name:** Should the new field be a direct `[openshell.gateway]` setting, a new subsection under a non-driver-specific supervisor area, or another shared startup object? It must not be nested under `[openshell.drivers.*]`.
2. **Material representation:** Should configuration accept one or more host file paths, inline PEM, a generated bundle, or both? The choice affects TOML safety, Helm/ConfigMap/Secret integration, path permissions, and how VM/Kubernetes stage the content.
3. **Transport contract:** Should the gateway normalize and copy the material into each sandbox launch, should each driver mount a configured path, or should the supervisor receive a generated file through a shared artifact? The answer must cover Docker, Podman, Kubernetes combined and sidecar, and VM without allowing sandbox-controlled environment overrides.
4. **Trust scope:** Should additional material be used only for the supervisor's upstream rustls client, or also be included in the combined sandbox process bundle? Existing proxy CA behavior does both, but the request specifically names network-supervisor destination trust.
5. **Validation boundary:** Should invalid material fail gateway startup, sandbox creation, supervisor startup, or more than one boundary? Existing code validates operator input at more than one boundary for proxy configuration.
6. **Reload/lifecycle:** Is restart-only behavior sufficient, and what should happen to already-running sandboxes after a gateway configuration/material change? No current network-supervisor CA reload path exists.
7. **Feature variants:** Is support required for builds without `bundled-ca-roots`, and if so should the shared root-store helper be changed to honor explicit PEM in that mode?
8. **Verification matrix:** Which shared TLS integration test plus driver contract tests provide enough evidence of uniform behavior without requiring a live private-CA deployment for every driver?

## External references

No external references were required for this phase. The repository already contains the relevant rustls APIs, feature selection, certificate parsing, and test patterns. External library/version questions can be revisited during Design or Implementation if the selected representation needs behavior not established by the current code.
