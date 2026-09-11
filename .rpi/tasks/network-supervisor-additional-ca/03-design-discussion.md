---
rpi_task: network-supervisor-additional-ca
workflow: rpi
phase: design
document_status: approved
updated: 2026-09-10T23:23:48Z
---

# Design discussion: additional CA materials for the network supervisor

## Approval status

This document is **approved** following explicit human approval. The design
phase gate is satisfied; the next RPI phase is the vertical structure outline.

The design was revised in response to feedback about distinguishing control-plane
gateway trust from destination trust. That separation is an explicit invariant
in Decision 5 and in the verification strategy below.

## Problem boundary and evidence

The gateway currently has no shared configuration for trust roots used by the
sandbox network supervisor. The relevant trust store is built in
`crates/openshell-supervisor-network/src/l7/tls.rs` and initialized by
`run_networking` in `crates/openshell-supervisor-network/src/run.rs`. In the
default `bundled-ca-roots` build, the client store contains Mozilla roots plus
the supplied system PEM; the TLS connector continues to perform normal
hostname verification.

The existing `--upstream-proxy-ca-bundle` option is not a suitable substitute:
it is paired with a corporate proxy, is currently exposed by the Podman path,
and is not a general shared setting. The driver matrix in
`02-research.md` shows that Docker, Podman, Kubernetes (combined and sidecar),
and VM all launch the same `openshell-sandbox` binary but stage files and
arguments differently. A gateway-host path therefore cannot simply be handed
to every supervisor.

The design below treats the four in-tree compute drivers as one contract:
configuration is read once by the gateway, normalized into operator-owned
certificate material, and delivered to the common supervisor through
driver-specific staging adapters. No driver-specific configuration field is
introduced.

## Goals

1. Add a documented TOML mechanism outside `[openshell.drivers.*]` for one or
   more additional PEM CA certificate files.
2. Make configured roots additive to the existing bundled/system/native roots.
3. Make a configured CA available to the shared network supervisor in Docker,
   Podman, Kubernetes combined, Kubernetes sidecar, and VM sandboxes.
4. Preserve hostname verification, policy enforcement, and the existing default
   behavior when the setting is absent.
5. Fail closed and report the configuration field/path when configured material
   is unreadable, empty, contains non-certificate PEM, or contains no usable
   X.509 trust anchor.
6. Reuse the same material for the supervisor's generated sandbox trust files
   where those files already provide the child-process TLS trust boundary.
7. Keep gateway control-plane mTLS trust strictly limited to the existing
   gateway-issued/client-configured CA material; destination CAs must never
   authenticate the gateway.

## Non-goals

- Replacing Mozilla, native, or image-provided trust roots.
- Disabling certificate verification, hostname verification, or network policy.
- Adding a per-sandbox or per-policy CA selector. This is a gateway-wide
  operator setting and applies to sandboxes launched by the selected gateway.
- Using the setting for gateway listener TLS, OIDC, gateway-to-gateway TLS,
  supervisor middleware, or interceptor endpoints. Those settings keep their
  existing CA configuration and lifecycle. In particular, the new bundle must
  never be merged into `OPENSHELL_TLS_CA`, the guest mTLS CA mount, or any
  control-plane gateway client trust store.
- Reusing or changing the meaning of `proxy_ca_bundle`. A corporate proxy CA
  remains a separate proxy-specific setting; an operator who needs one CA for
  both purposes can configure both settings.
- Downloading CA material from a URL, accepting DER-only input, accepting
  private keys, or silently accepting arbitrary PEM blocks.
- Hot reload. Gateway TOML and the network supervisor trust store remain
  startup-oriented.
- Changing raw socket policy, SSRF policy, or the semantics of a network mode
  that has no supervisor TLS client. In a non-proxy mode, the additional bundle
  is exposed through the existing child-process trust-file mechanism when
  process supervision is enabled, but it does not create a new supervisor TLS
  interception path.
- Adding support for a custom remote compute driver that does not implement the
  shared supervisor-material launch contract. The required driver matrix is the
  four in-tree drivers identified above.

## Decision 1: configuration placement and shape

### Decision

Add a nested network-supervisor section under the existing non-driver-specific
supervisor section:

```toml
[openshell.supervisor.network]
# Each file is gateway-local and may contain one or more CERTIFICATE blocks.
additional_ca_cert_paths = [
  "/etc/openshell/certs/internal-ca.crt",
  "/etc/openshell/certs/vendor-chain.pem",
]
```

`additional_ca_cert_paths` is an optional ordered list. An omitted list or an
empty list means that no additional material is configured. The paths are
interpreted by the gateway process, not by the sandbox image or by a compute
driver. The list is normalized into one bundle before it reaches a driver.

The section is deliberately separate from `[openshell.gateway.tls]`,
`guest_tls_*`, and the existing `[[openshell.supervisor.middleware]]`
`tls_ca_cert_path`. All are different TLS trust boundaries.

### Options considered

| Option | Consequences | Result |
|---|---|---|
| Put a field directly in `[openshell.gateway]` | Clearly gateway-wide and easy for the current parser, but makes a network-supervisor trust setting look like listener/authentication configuration and grows an already broad section. | Rejected in favor of a more precise supervisor namespace. |
| Put `additional_ca_cert_paths` directly in `[openshell.supervisor]` | Fewer structs and consistent with the current middleware array, but leaves future network-supervisor settings mixed with middleware registrations. | Rejected; the nested table makes ownership explicit. |
| Put the setting under each `[openshell.drivers.<name>]` table | Each driver could use its native mount mechanism, but violates the request, duplicates configuration, and makes behavior diverge. | Rejected. |
| Accept one path to one pre-combined bundle | Simple transport, but forces operators to build and maintain a separate aggregate file and does not naturally express multiple mounted CA materials. | Rejected. |
| Accept a list of file paths | Matches existing path-based TLS settings, supports multiple materials, keeps PEM out of TOML, and lets Helm mount a `ca.crt` source. | **Selected.** |
| Accept inline PEM in TOML, or both inline PEM and paths | Avoids a gateway source mount in some deployments, but makes TOML/Helm escaping and review difficult, increases config size, and creates a second validation/transport form without repository precedent for this boundary. | Rejected for the first version. |

### Consequences

- The new setting is static TOML configuration and is covered by the existing
  `deny_unknown_fields` behavior.
- Kubernetes/Helm deployments must mount the operator's source ConfigMap (key
  `ca.crt`) into the gateway at a path used by this list. The Helm chart should
  expose this as a supervisor-network value and render the global TOML section;
  it must not render the setting into `[openshell.drivers.kubernetes]`.
- A list containing the same certificate more than once is valid. Duplicate
  roots are harmless and do not change trust semantics.

## Decision 2: load, validate, and normalize at gateway startup

### Decision

The gateway reads every configured path during startup, before constructing the
compute driver runtime. It creates a normalized, in-memory
`NetworkSupervisorTrustBundle` containing only canonical PEM certificate
blocks, a certificate count, and a non-secret content digest for diagnostics.
The source path names are retained only for actionable errors and are not
passed to sandboxes.

Validation is strict for explicitly configured files:

1. A path must be non-empty, readable, and resolve to file content.
2. Every PEM item must be an X.509 `CERTIFICATE` block. Private keys and other
   PEM blocks are rejected.
3. At least one certificate must be present across each configured file.
4. Every certificate must be parseable as usable DER for a rustls trust store;
   a file with one valid certificate and one unusable certificate is rejected,
   rather than partially accepted.
5. The normalized bundle is additive input; it is never used as a replacement
   for default roots.

The gateway reports errors with the configuration section and source path, but
never logs certificate bytes. A bad configured file is a gateway configuration
error, not an instruction to continue with only public roots.

The shared `DriverStartupContext` receives the normalized bundle (or an
operator-owned handle to it) in addition to the existing parsed config and TLS
context. Drivers do not reread the original gateway paths. At sandbox launch,
the supervisor validates the staged bundle again so a missing, truncated, or
unreadable delivery fails closed rather than silently falling back to defaults.

### Options considered

| Option | Consequences | Result |
|---|---|---|
| Let every driver read the configured gateway paths | Does not work for Kubernetes pods or VM guests, duplicates parsing/error behavior, and exposes host path assumptions to drivers. | Rejected. |
| Read only inside `openshell-sandbox` at sandbox startup | A bad gateway config is discovered late, every driver must transport source paths, and an invalid setting could be mistaken for an unset one. | Rejected. |
| Pass raw PEM through supervisor argv/env | Avoids mounted artifacts, but puts potentially large certificate data in container/Pod specs and VM launch metadata and creates different size/escaping behavior across drivers. | Rejected. |
| Read and strictly normalize once at gateway startup, then validate again at the supervisor boundary | Gives one validation contract, removes gateway-host path visibility from guests, supports all drivers, and makes failure timing predictable. | **Selected.** |

### Feature-variant decision

The explicit bundle must be honored in both rustls build variants. With
`bundled-ca-roots`, the store remains Mozilla roots plus system/native bundle
plus the normalized additional bundle. Without `bundled-ca-roots`, the store
remains native roots plus the explicit additional bundle. This deliberately
changes the current helper's treatment of *explicitly supplied* PEM in the
native-only build so the new setting cannot be accepted and then ignored. The
existing no-setting behavior remains unchanged.

The system CA discovery behavior remains unchanged: the current helper selects
the first non-empty well-known system bundle. The new configured material is
an explicit overlay, not a replacement for or a redesign of system discovery.

## Decision 3: one staged-file launch contract for every in-tree driver

### Decision

The common supervisor contract is:

1. The gateway makes one normalized bundle available to the driver.
2. The driver stages it read-only at the fixed in-sandbox path
   `/etc/openshell-tls/network-additional-ca.crt`, represented by a constant in
   `openshell-core::container_paths`.
3. The driver passes that path using the dedicated operator-only supervisor
   argument `--network-additional-ca-bundle /etc/openshell-tls/network-additional-ca.crt`.
   The new argument is not read from conventional sandbox proxy/environment variables;
   user template variables and image `ENV` cannot select, replace, or suppress
   the operator-owned argument.
4. The supervisor reads the staged file during its one-time networking
   initialization and fails startup if the explicitly requested file is not
   valid.

The driver adapters are intentionally different only at the staging boundary:

| Driver/topology | Staging and supervisor launch contract | Deliberately absent |
|---|---|---|
| Docker | Bind-mount the gateway-normalized host artifact read-only and append the dedicated argument to the existing supervisor command. | No Docker config field; no sandbox environment override. |
| Podman | Bind-mount the same kind of host artifact read-only and append the same argument. Keep `proxy_ca_bundle` independent. | No reuse of the proxy-only mount/validation. |
| Kubernetes combined | The driver publishes the normalized PEM as a gateway-managed ConfigMap (`ca.crt`) in each target sandbox namespace, mounts it read-only into the agent/supervisor container, and appends the argument. | The network-init container does not receive the material. |
| Kubernetes sidecar | The same managed ConfigMap is mounted only into the network sidecar, and the sidecar command receives the argument. The sidecar's generated combined trust files remain the process supervisor's source through existing sidecar control. | The network-init container and unrelated workload containers do not receive the CA volume. |
| VM | Copy the normalized PEM into the per-sandbox overlay at the fixed guest path and extend the VM guest-init launch contract so the supervisor receives the same dedicated argument. The path is not supplied as a user-controlled guest environment value. | No host path is assumed to exist inside the guest. |

The Kubernetes ConfigMap is appropriate because CA material is public
certificate data, not a private key or credential. It should have a stable
name derived from the gateway identity, an OpenShell management label, and
server-side apply/update semantics so new sandboxes see the current startup
bundle without accumulating one object per sandbox. In shared mode it is
managed in the sandbox namespace; in managed/operator modes the driver applies
it in each target namespace just as it already copies required TLS material.
The Helm RBAC and any documented operator-managed namespace permissions must
include the narrowly scoped ConfigMap operations required by this path.

### Why not pass a ConfigMap reference as the core configuration?

A Kubernetes object reference would be a poor shared schema: it would not
transport the material to Docker, Podman, or VM, and it would make the
non-Kubernetes configuration model depend on Kubernetes naming. The core
configuration is therefore a gateway-local file list; Kubernetes converts the
normalized shared material to its native volume primitive at the driver
boundary.

### Consequences

- A new shared launch/material type is required rather than adding equivalent
  fields to four driver config structs.
- Local container drivers need a gateway-owned artifact location that the
  container engine can access, following the existing host-path assumptions for
  supervisor and guest TLS mounts.
- Kubernetes deployments gain a managed, public ConfigMap in sandbox
  namespaces and a corresponding RBAC/documentation requirement. Existing
  sandboxes keep the trust material loaded at their startup; updating the
  ConfigMap alone does not hot-reload their rustls client.
- VM overlay preparation becomes part of the same trust-material contract and
  must happen before the guest init script starts the supervisor.
- The staged file contains public CA data, but it is still read-only and kept
  under reserved OpenShell control paths to prevent sandbox configuration from
  changing the operator boundary.

## Decision 4: trust scope and additive root-store behavior

### Decision

The normalized bundle is used in two existing trust consumers:

1. **Supervisor upstream TLS.** `build_upstream_client_config` receives the
   system/default roots plus the additional bundle. A destination certificate
   signed by a configured private CA can pass only when its hostname also
   matches the requested server name. A self-signed leaf without a configured
   trust anchor remains rejected.
2. **Supervisor-generated child trust files.** When the network supervisor
   already publishes `ca_file_paths`, the additional certificates are included
   in both the standalone additive file and the combined system bundle. This
   keeps workload clients that use the existing `NODE_EXTRA_CA_CERTS`,
   `DENO_CERT`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, or
   `GIT_SSL_CAINFO` mechanism consistent with the supervisor. If configured
   additional roots are present in a non-proxy network mode, the supervisor
   publishes an additional-only/combined pair for this existing child-process
   mechanism; it does not invent TLS interception for that mode.

The existing generated OpenShell MITM CA remains in the same files in proxy
mode. The combined file remains system roots + configured additional roots +
OpenShell's generated CA. The standalone additive file contains the generated
CA and configured additional roots needed by clients that only honor the
additive path. No host trust store is modified.

The generic additional bundle is **not** silently substituted for
`proxy_ca_bundle` when an `https://` corporate proxy is configured. The proxy
listener's existing explicit CA option remains the source for proxy-specific
TLS validation; an operator may configure both settings when the same private
PKI signs both the proxy and destinations.

### Options considered

| Option | Consequences | Result |
|---|---|---|
| Add roots only to the L7 supervisor upstream `ClientConfig` | Smallest code change, but raw/relayed workload TLS clients would still fail to trust the same private CA and sidecar/combined trust behavior would be surprising. | Rejected. |
| Add roots only to child environment bundles | Does not help the supervisor's own upstream re-encryption handshake, which is the failing path for inspected HTTPS. | Rejected. |
| Add roots to the shared supervisor store and the existing child trust-file path | Covers both supervisor-verified and relayed workload TLS without changing policy or host trust; reuses existing sidecar propagation. | **Selected.** |
| Replace default roots with the configured bundle | Could make private PKI work but breaks public/default trust and violates the task constraint. | Rejected. |

### Security consequences

- Trust is broadened only for sandboxes launched by the operator-configured
  gateway, and network policy/SSRF/L7 checks still run first.
- Normal rustls hostname verification remains active. There is no
  `danger_accept_invalid_certs` or “trust any self-signed leaf” mode.
- The operator is responsible for the scope of each configured CA: every
  destination certificate chaining to it becomes trustable wherever policy
  permits the connection. Documentation should warn against putting private
  keys in the bundle and should recommend a narrowly scoped CA.
- Certificate contents are never logged or placed in task artifacts. Logs may
  report the number of loaded certificates, a non-secret digest, and the named
  configuration path/field.

## Decision 5: keep gateway control-plane trust separate

### Decision

The implementation must maintain two disjoint trust domains inside every
sandbox:

1. **Gateway control-plane trust** remains the existing guest mTLS material.
   The drivers continue to mount the gateway CA at the existing client-TLS path
   (`/etc/openshell/tls/client/ca.crt` for containers and
   `/opt/openshell/tls/ca.crt` for VM guests), together with the client
   certificate and key. `openshell-core::grpc_client::build_plain_channel`
   reads `OPENSHELL_TLS_CA`, `OPENSHELL_TLS_CERT`, and `OPENSHELL_TLS_KEY`,
   constructs a `ClientTlsConfig` with exactly that CA, and preserves the
   configured gateway server name. It must not read, append, or fall back to
   the network additional bundle.
2. **Destination trust** is the new network-supervisor material staged at
   `/etc/openshell-tls/network-additional-ca.crt` and consumed by the network
   TLS/root-store path and, where applicable, the existing child-process trust
   files under `/etc/openshell-tls`. It must never be mounted over, copied
   into, or concatenated with the guest mTLS CA path.

This means a certificate authority configured for private destination services
cannot authenticate a server pretending to be the OpenShell gateway. All
OpenShell supervisor-session, policy, log-push, and other gateway gRPC
connections continue through the explicit `grpc_client` trust configuration.
The same invariant applies to Kubernetes sidecar bootstrap: the sidecar
control channel may transfer generated destination-trust file paths to the
process supervisor, but it does not transfer or replace gateway mTLS material.

The separation is structural, not only conventional:

- use distinct configuration/data types for `GatewayTlsMaterial` and
  `NetworkSupervisorTrustBundle`;
- use distinct constants, volume names, mount roots, and test fixtures;
- do not use `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, or the combined destination
  bundle as the source for gateway gRPC TLS; and
- require any future OpenShell gateway TLS client to use the explicit gateway
  trust helper rather than ambient process trust.

A sandbox workload may intentionally use the destination bundle for arbitrary
TLS destinations permitted by network policy. That is separate from
authentication of the control-plane gateway and must not be described as
additional gateway trust.

### Options considered

| Option | Consequences | Result |
|---|---|---|
| Merge gateway mTLS and destination roots into one combined CA file | Simplifies file delivery, but lets a destination CA authenticate a fake gateway and violates the existing explicit-trust security boundary in `grpc_client.rs`. | Rejected. |
| Keep the existing gateway CA path and add a separate network-only bundle | Preserves the current gateway identity boundary while allowing private destination PKI. It requires separate mounts and explicit tests, but the repository already has distinct control and proxy TLS paths. | **Selected.** |
| Add a per-host trust map that excludes the gateway hostname | More complex and fragile than separate client configurations; hostname exclusion is not a substitute for a separate trust anchor set. | Rejected. |

### Required regression tests

The implementation must include an isolation test using two generated private
CAs: one representing the gateway CA and one representing a destination CA.
With only the destination CA configured in `[openshell.supervisor.network]`:

- a destination server signed by the destination CA succeeds through the
  network trust path;
- a gateway TLS server signed by the destination CA is rejected by
  `grpc_client`; and
- a gateway TLS server signed by the configured guest/gateway CA continues to
  succeed, including normal server-name verification.

Driver launch tests must also assert that the new destination mount/argument
never replaces or augments `OPENSHELL_TLS_CA` and the existing guest mTLS
mount. The no-additional-CA path must retain the current control-plane trust
configuration byte-for-byte.

## Failure behavior and observability

### Failure points

- **Gateway startup:** unreadable, empty, malformed, mixed-key, or unusable
  configured input stops gateway initialization with an error naming
  `[openshell.supervisor.network].additional_ca_cert_paths` and the failing
  path. The gateway does not start with the setting silently ignored.
- **Driver/sandbox creation:** failure to create/update a local artifact,
  Kubernetes ConfigMap, volume reference, or VM overlay fails the sandbox
  operation before the workload is considered ready. The error names the
  staging boundary and never includes PEM bytes.
- **Supervisor startup:** failure to read or validate the staged file is fatal
  when the dedicated argument is present. It does not fall back to the default
  root store. Existing behavior for an omitted argument is unchanged.
- **TLS handshake:** a valid configured CA still cannot bypass hostname
  verification, destination policy, or certificate-chain validation. The
  normal upstream handshake error is retained for an untrusted/mismatched
  destination.

Successful load/staging and failure diagnostics should follow existing
configuration/TLS logging conventions: report presence/count and the relevant
path or digest, never certificate contents. The sandbox can emit the existing
configuration-state OCSF event for trust initialization, with failure severity
when an explicitly requested bundle cannot be loaded. No new per-request log
should include a CA or certificate chain.

## Lifecycle, migration, and rollback

- The gateway reads and validates the source files once at startup. Changing a
  source file, the TOML list, or the Helm value requires a gateway restart.
- A restarted gateway uses the new normalized bundle for newly created or
  restarted sandboxes. Already-running supervisors retain the root store and
  child trust files created at their startup; no live update is promised.
- A Kubernetes ConfigMap update is a delivery/cache mechanism, not a reload
  mechanism. A running supervisor does not rebuild its rustls client because a
  volume changed.
- Removing the setting and restarting the gateway returns new sandboxes to the
  existing default/system trust behavior. Existing sandboxes must be restarted
  to remove previously staged additional roots.
- The existing `proxy_ca_bundle` configuration remains backward compatible and
  keeps its proxy pairing rules. No migration of existing driver TOML keys is
  required.
- Rollback is removal of the new global section (or rollback of the gateway
  image/chart) followed by the normal gateway and sandbox restart lifecycle.
  An invalid new bundle prevents startup rather than causing a silent trust
  downgrade.

## Interface and data changes for the future outline

The implementation outline should cover these boundaries without editing them
in this design phase:

1. **Gateway config:** add a nested network supervisor config type under
   `SupervisorFileSection`, strict path-list parsing, startup loader errors, and
   parser tests in `crates/openshell-server/src/config_file.rs`.
2. **Gateway startup context:** load/normalize the bundle alongside existing
   middleware startup validation in `crates/openshell-server/src/lib.rs` and
   carry an owned/shared handle through
   `crates/openshell-server/src/compute/driver_config.rs` and built-in driver
   construction.
3. **Shared sandbox contract:** add the fixed destination-trust path and
   dedicated supervisor argument, pass the material into `run_networking`, and
   update `openshell-supervisor-network/src/l7/tls.rs` and `src/run.rs` so
   explicit roots are honored in both feature variants and child trust files
   remain additive. Keep `openshell-core/src/grpc_client.rs` on the existing
   explicit `OPENSHELL_TLS_CA` path; do not route gateway gRPC through the new
   bundle.
4. **Driver adapters:** implement the staged-file/argument contract in
   Docker, Podman, Kubernetes combined/sidecar, and VM paths. Kubernetes must
   add managed ConfigMap handling, volume mounts, RBAC, and topology-specific
   assertions; VM must cover overlay preparation and guest-init launch.
5. **Documentation/config delivery:** update `docs/reference/gateway-config.mdx`,
   `architecture/sandbox.md`, the RFC 0003 schema reference if it remains the
   canonical schema document, Helm values/templates/README, and any driver
   README text that currently describes the proxy-only CA path.

## Verification strategy

### Shared configuration and trust tests

- Parse the new nested table, accept multiple paths, reject unknown fields, and
  preserve an empty/default configuration.
- Use generated test certificates and temporary files to cover readable
  multi-certificate input, empty files, malformed PEM, private-key blocks,
  unusable DER, and missing paths. Assert errors identify the field/path and do
  not contain certificate bytes.
- Build the upstream rustls client with a generated private CA and a server
  certificate for the expected hostname. Assert success with the additional
  bundle, failure without it, failure for a mismatched hostname, and continued
  success for a default/public root. Run the root-store assertions for both
  bundled and native feature configurations where the workspace supports them.
- Test that configured roots are present in the standalone and combined child
  trust files, while the no-setting path produces the current files/behavior.
- Exercise the two-CA control-plane isolation case: a destination CA can verify
  a destination through the network path but cannot verify a fake gateway
  through `grpc_client`; the separately configured gateway CA still verifies
  the real gateway certificate. Assert that `OPENSHELL_TLS_CA` and its client
  identity paths are unchanged.

### Driver contract tests

Use one shared material fixture and test the launch specification at each
boundary rather than duplicating a full TLS server test four times:

- Docker: configured bind and argument; omitted configuration has no bind or
  argument.
- Podman: configured bind and argument; proxy CA behavior remains separate.
- Kubernetes: combined and sidecar mount/argument placement; ConfigMap data and
  permissions; no additional CA in network-init or unrelated containers; RBAC
  render coverage.
- VM: staged overlay file, private/read-only material expectations, and the
  guest-init/supervisor argument contract for both supported launch backends.
- A shared integration test at the supervisor boundary proves that every
  driver-delivered fixed path is consumed by the same root-store/TLS code. A
  live private-CA deployment for every driver is not required for unit coverage,
  but the existing relevant e2e path should be extended if its infrastructure
  can exercise a configured global bundle.

## Decision summary for human approval

1. **Placement:** `[openshell.supervisor.network].additional_ca_cert_paths`, not
   any compute-driver table.
2. **Representation:** one or more gateway-local PEM file paths, normalized at
   gateway startup; no inline PEM or remote URL in the first version.
3. **Propagation:** one shared normalized destination bundle delivered through a
   read-only, fixed-path supervisor launch contract, with Docker/Podman bind
   mounts, Kubernetes managed ConfigMaps, and VM overlay staging.
4. **Trust:** additive only to bundled/system/native destination roots and the
   existing child trust-file mechanism; hostname and policy checks remain
   mandatory.
5. **Isolation:** gateway mTLS continues to use only the existing explicit
   `OPENSHELL_TLS_CA`/client identity material. The new destination bundle is
   never merged into or substituted for gateway control-plane trust.
6. **Lifecycle:** startup-only, fail closed at gateway, staging, and supervisor
   boundaries; no hot reload and no silent fallback when explicitly configured.
7. **Compatibility:** existing configurations and proxy-specific CA behavior
   remain unchanged when the new list is absent.

**Approval record:** The user explicitly approved these seven decisions,
including Decision 5's strict separation between gateway mTLS trust and
destination trust, the nested global section, gateway-local path
representation, Kubernetes managed ConfigMap transport, child-process
trust-file inclusion, and startup-only lifecycle.
