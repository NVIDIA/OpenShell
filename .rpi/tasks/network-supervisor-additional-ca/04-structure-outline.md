---
rpi_task: network-supervisor-additional-ca
workflow: rpi
phase: outline
document_status: approved
updated: 2026-09-10T23:39:00Z
---

# Structure outline: additional CA materials for the network supervisor

## Outline status and approval gate

The design artifact (`03-design-discussion.md`) is approved. This outline is
still a **draft**: `state.json.approvals.outline` remains `false`, the task
remains in the `outline` phase, and implementation must not begin until the
human explicitly approves this outline. Approval of the design is not approval
of the implementation order or the file-level plan below.

The outline preserves these design invariants:

- Configuration is global at
  `[openshell.supervisor.network].additional_ca_cert_paths`, never under a
  compute-driver table.
- Gateway startup reads and strictly normalizes each configured PEM file once.
  Drivers receive normalized material or a gateway-owned staged artifact, not
  the operator's source paths.
- The bundle augments bundled/system/native destination roots and the existing
  child-process trust files. It never replaces default roots, disables
  hostname verification, or changes network policy.
- Gateway control-plane mTLS remains on its existing explicit
  `OPENSHELL_TLS_CA`/client-identity path. The destination bundle has a
  separate path, data type, volume, and test fixture.
- Docker, Podman, Kubernetes combined, Kubernetes sidecar, and VM all use the
  same supervisor argument and guest path, with driver-specific staging only at
  the boundary.
- Invalid configured material, failed staging, or a missing/truncated staged
  file fails closed. No certificate or key contents may appear in logs or
  artifacts.
- A missing setting preserves the existing behavior byte-for-byte where the
  current tests can observe it. Startup-only behavior is intentional; no hot
  reload is added.

## Overview checklist

- [ ] 1. Add the global configuration, startup normalization, gateway-owned
      material handle, and unsupported-driver rejection.
- [ ] 2. Add the common supervisor launch contract and additive rustls/child
      trust behavior, including control-plane isolation tests.
- [ ] 3. Adapt the Docker driver to stage and pass the common material.
- [x] 4. Adapt the Podman driver without conflating destination trust with
      `proxy_ca_bundle`.
- [x] 5. Adapt Kubernetes ConfigMap delivery for combined and sidecar
      topologies.
- [x] 6. Adapt VM overlay and guest-init delivery for both supported launch
      backends.
- [ ] 7. Deliver the configuration through Helm and update architecture,
      reference, RFC, and driver documentation.
- [ ] 8. Run cross-driver regression/e2e verification and close the lifecycle,
      security, and rollback checks.

## Shared launch contract

The following contract is established in slices 1 and 2 and is consumed by all
four driver adapters:

| Boundary | Required value |
| --- | --- |
| Gateway configuration | `[openshell.supervisor.network].additional_ca_cert_paths` is an ordered list of gateway-local PEM file paths. |
| Normalized representation | `NetworkSupervisorTrustBundle` contains canonical certificate PEM, certificate count, a non-secret digest, and a gateway-owned host artifact path where a local/VM adapter needs one. Its `Debug` representation must not include PEM bytes. |
| Guest destination path | `openshell_core::container_paths::NETWORK_ADDITIONAL_CA_BUNDLE_PATH` with value `/etc/openshell-tls/network-additional-ca.crt`. |
| Supervisor argument | Dedicated operator-only `--network-additional-ca-bundle /etc/openshell-tls/network-additional-ca.crt`; it is an argv value controlled by the driver, not a conventional sandbox environment variable. |
| Supervisor behavior | Validate the explicitly requested staged PEM before use; add it to the normal destination root store and to existing child trust files. Do not fall back to public roots when the requested file cannot be read or parsed. |
| Control-plane behavior | Continue to read `OPENSHELL_TLS_CA`, `OPENSHELL_TLS_CERT`, and `OPENSHELL_TLS_KEY` from the existing guest mTLS mounts. Never use the destination bundle for gateway gRPC. |
| No configuration | No destination mount, no dedicated argument, no new ConfigMap/overlay file, and the current default/system/proxy behavior remains unchanged. |

The gateway-owned host artifact is a normalized copy under the existing
OpenShell state/runtime ownership boundary, with a stable path that satisfies
the existing local-container host-path assumptions. The source paths from the
TOML list are used for validation errors only. Kubernetes receives the
normalized bytes and does not receive the host path.

## Ordered vertical slices

### Slice 1 — Global configuration and startup material contract

**Outcome and boundaries**

The gateway can parse the new non-driver-specific TOML section, read every
configured source file before constructing a compute driver, reject invalid
material with an actionable field/path error, and expose one shared normalized
bundle through `ServerStartupConfig` and `DriverStartupContext`. A selected
remote or unsupported custom driver is rejected before connection/construction
when a bundle is configured; it must not silently discard the setting.

This slice deliberately stops before any sandbox receives the bundle. Its
independent verification is the gateway configuration/startup boundary.

**Files/components expected to change**

- `crates/openshell-server/src/config_file.rs`
  - Add the nested `SupervisorFileSection.network` configuration type and the
    `additional_ca_cert_paths` list with the existing strict unknown-field
    behavior.
  - Keep the list optional/empty by default and reject empty path entries with
    the configuration field named in the error.
- `crates/openshell-server/src/network_trust.rs` (new)
  - Implement startup loading, strict PEM item validation, usable-certificate
    validation, canonical PEM normalization, certificate counting, digesting,
    and gateway-owned host artifact creation.
  - Keep source path names for errors, never for guest launch arguments.
  - Write the artifact atomically and with permissions appropriate for the
    local engine/VM driver to read; do not expose it through environment
    variables or logs.
- `crates/openshell-core/src/network_trust.rs` (new) and
  `crates/openshell-core/src/lib.rs`
  - Define the shared `NetworkSupervisorTrustBundle`/material accessors used
    by the server and in-tree driver crates. Provide a redacted `Debug`
    implementation and read-only access to normalized PEM, count, digest, and
    the gateway-owned artifact path.
- `crates/openshell-server/src/cli.rs`
  - Invoke normalization during `prepare_server_config` after TOML loading and
    before driver construction; retain the owned bundle in
    `ServerStartupConfig`.
- `crates/openshell-server/src/lib.rs`
  - Carry the bundle through the startup context and expose it to registered
    in-tree factories without putting it into the public driver TOML config.
  - Reject a configured bundle for remote endpoints and unrecognized/custom
    driver registrations before opening the remote socket or invoking an
    unsupported factory. The accepted names are only the four in-tree
    adapters: Docker, Podman, Kubernetes, and VM.
- `crates/openshell-server/src/compute/driver_config.rs` and
  `crates/openshell-server/src/compute/driver_config/builtin.rs`
  - Extend `DriverStartupContext` and its test builders with the shared
    bundle handle. Keep existing driver table deserialization unchanged.
- `crates/openshell-server/src/compute/mod.rs`
  - Thread the context field through the common driver-build path without
    changing the protobuf compute-driver API.

**Implementation notes and dependencies**

1. Parse the global table independently of `file.openshell.drivers`; do not
   make `driver_table()` merge this setting into a driver config.
2. For every configured source file, read all PEM items. Reject unreadable,
   empty, non-certificate, private-key/mixed, malformed, or unusable
   certificate content rather than accepting the valid subset. Require at
   least one usable certificate in each configured file.
3. Normalize to canonical certificate PEM blocks. Compute a non-secret digest
   only after normalization. Error text may identify
   `[openshell.supervisor.network].additional_ca_cert_paths` and the source
   path, but must not contain bytes from the input.
4. Materialize one gateway-owned artifact for local/VM adapters. The artifact
   is public CA data, but the directory remains an OpenShell-owned control
   path and the file is replaced atomically. The type must make it impossible
   for a later adapter to accidentally use the original source path.
5. Preserve `None`/empty semantics all the way through startup. The remote
   rejection must happen before any remote driver connection and before an
   external driver can report readiness.

**Tests to add or update**

- `crates/openshell-server/src/config_file.rs` tests:
  - Parse the nested section with one and multiple paths.
  - Preserve omitted/empty defaults.
  - Reject unknown keys, empty list entries, and attempts to place the field
    in a driver table.
- `crates/openshell-server/src/network_trust.rs` tests:
  - Normalize a multi-certificate PEM fixture and assert count/digest/artifact
    content without exposing bytes in diagnostics.
  - Reject missing/unreadable, empty, malformed, non-certificate, private-key,
    mixed valid/invalid, and certificate-free files.
  - Assert every failure names the field and failing source path and does not
    contain a certificate fixture body.
  - Assert the redacted debug/log representation contains only presence/count
    and digest, never PEM.
- `crates/openshell-server/src/compute/driver_config.rs` and
  `crates/openshell-server/src/lib.rs` tests:
  - Verify the bundle is available to an in-tree startup context.
  - Verify a configured bundle rejects an endpoint override, unknown remote
    driver, and unsupported custom registration before connection/build.
  - Verify no bundle leaves remote/custom-driver behavior unchanged.
- `crates/openshell-core/src/network_trust.rs` tests for accessor and redacted
  representation behavior.

**Automated commands and expected signals**

```shell
cargo test -p openshell-core network_trust
cargo test -p openshell-server config_file
cargo test -p openshell-server network_trust
cargo test -p openshell-server driver_config
cargo test -p openshell-server configured_compute_driver
cargo fmt --all -- --check
```

Expected signals are successful tests, no PEM content in captured diagnostics,
and no changes to unrelated driver-table parsing tests. The full workspace
format check is repeated after all slices.

**Process-level verification (amended during implementation)**

Per explicit user direction on 2026-09-11, these startup behaviors are verified
by an automated process-level test rather than a manual check. The test launches
the real `openshell-gateway` binary with temporary configuration and generated
certificate material and asserts:

1. A valid global list reports only certificate count/digest metadata before an
   unsupported custom driver is rejected, without exposing certificate bytes.
2. A missing path, empty file, and private-key file exit before server/driver
   startup with the field and source path in the error and no material leakage.
3. A configured remote endpoint is rejected with the incompatible-combination
   error before any socket connection or remote-driver construction is attempted.

Command:

```shell
cargo test -p openshell-gateway --no-default-features --test network_trust_startup
```

No separate manual verification remains for Slice 1. Live cross-driver trust
behavior remains in Slice 8's e2e matrix.

**Failure, rollback, migration, and compatibility behavior**

- Any validation or artifact-write failure is a gateway startup/configuration
  failure. Do not continue with public roots only.
- Removing the global section returns the existing startup path and does not
  require a migration of any driver TOML.
- Rollback is removing the new section or reverting the gateway binary. No
  existing source file is rewritten.
- Existing gateway mTLS/TLS fields and all driver-specific config structs are
  untouched by this slice.

**Observability and security**

Use a count and non-secret digest for successful normalization if a startup log
is useful. Do not log PEM, DER, source file contents, private-key-looking
blocks, or the normalized artifact body. Keep the destination bundle type
structurally separate from gateway TLS material.

**Dependencies**

This is the prerequisite for every later slice. No driver or supervisor code
should be changed until this contract and its startup failure behavior compile
and test.

- [x] Slice 1 complete

### Slice 2 — Common supervisor TLS and child trust behavior

**Outcome and boundaries**

The common `openshell-sandbox`/network supervisor consumes the fixed staged
path in both bundled-root and native-root builds. A valid configured CA is
additive for upstream destination TLS and for the existing child-process trust
files; an invalid explicitly requested staged file is fatal. The existing
proxy-specific CA remains independent, and gateway gRPC continues to use only
its explicit mTLS CA.

This slice can be verified with a staged fixture passed directly to the
supervisor boundary before any compute driver is involved.

**Files/components expected to change**

- `crates/openshell-core/src/container_paths.rs`
  - Add the reserved destination-trust path constant and document its
    separation from `TLS_CA_MOUNT_PATH`, `TLS_CERT_MOUNT_PATH`,
    `TLS_KEY_MOUNT_PATH`, and `PROXY_CA_MOUNT_PATH`.
- `crates/openshell-sandbox/src/main.rs` and `src/lib.rs`
  - Add the operator-only `--network-additional-ca-bundle` argument and pass
    it explicitly into `run_networking`; do not give it an environment alias.
  - Preserve the existing sidecar/process bootstrap signatures and existing
    gateway mTLS environment handling.
- `crates/openshell-sandbox/src/sidecar_control.rs`
  - Update only the shared networking/bootstrap value plumbing or assertions
    required to preserve the existing sidecar trust-file handoff; do not pass
    gateway client credentials through the destination bundle.
- `crates/openshell-supervisor-network/src/l7/tls.rs`
  - Extend root-store construction to add the explicitly supplied bundle after
    normal bundled/system/native roots in both feature variants.
  - Add strict staged-bundle parsing and make hostname verification remain on
    the normal rustls connector.
  - Extend `write_ca_files` so configured roots are present in the standalone
    additive file and combined file. With no configured roots, retain current
    bytes/paths.
- `crates/openshell-supervisor-network/src/run.rs`
  - Validate the dedicated path at networking initialization, including when
    process supervision is enabled without proxy mode.
  - Make an explicitly requested bundle failure return a startup error rather
    than taking the existing proxy TLS-disabled fallback.
  - Keep the existing generated OpenShell CA and proxy CA composition separate;
    only destination material is shared with the destination trust files.
- `crates/openshell-supervisor-network/src/upstream_proxy.rs`
  - Keep `--upstream-proxy-ca-bundle` parsing, validation, and pairing rules
    unchanged. Any helper reuse must be limited to generic PEM validation and
    must not merge the two configuration meanings.
- `crates/openshell-supervisor-process/src/child_env.rs`, and any required
  call-site updates in `src/process.rs`/`src/ssh.rs`
  - Assert that existing TLS environment variables point to the generated
    standalone/combined paths containing the additive material, not to the
    gateway mTLS CA.
- `crates/openshell-core/src/grpc_client.rs`
  - Keep the explicit gateway TLS configuration unchanged and add the two-CA
    isolation fixture/tests. Do not make the destination bundle ambient trust.

**Implementation notes and dependencies**

- The supervisor must validate all PEM blocks in the staged file, even though
  gateway startup already normalized the material. This catches missing,
  truncated, or replaced mounts at the sandbox boundary.
- In bundled-root mode, retain Mozilla roots and add system plus configured
  roots. In native-root mode, retain native roots and add configured roots;
  explicitly supplied roots must not be discarded merely because the build
  lacks `bundled-ca-roots`.
- In proxy mode the standalone file contains the generated OpenShell CA plus
  configured destination roots, and the combined file contains system roots,
  configured destination roots, and the generated CA. In non-proxy mode,
  configured roots create the existing standalone/combined pair for child
  processes but do not create a new interception path.
- The argument is an operator-owned launch input. User command arguments,
  image `ENV`, and proxy environment variables cannot choose a different file
  or suppress it.
- OCSF/tracing messages may report trust initialization status, count, and
  digest/path category, but never certificate data. A requested-file failure
  is a configuration-state failure, not a warning that permits downgrade.

**Tests to add or update**

- `crates/openshell-supervisor-network/src/l7/tls.rs`:
  - Root-store tests for a generated private destination CA, public/default
    roots, hostname mismatch, malformed/private-key PEM, and both feature
    variants.
  - `write_ca_files` tests for proxy and non-proxy/additional-only cases,
    checking standalone and combined contents and preserving the no-setting
    output.
- `crates/openshell-supervisor-network/src/run.rs`:
  - Missing/unreadable/empty/malformed staged bundle is fatal when the
    dedicated argument is present.
  - Omitted argument follows the existing network-mode behavior.
- `crates/openshell-supervisor-process/src/child_env.rs` and process/SSH tests:
  - Existing TLS environment variables receive the additive file pair and do
    not receive `OPENSHELL_TLS_CA`.
- `crates/openshell-core/src/grpc_client.rs`:
  - Two generated CAs: destination TLS succeeds through the network trust
    helper; a destination-signed fake gateway is rejected; the real gateway
    CA still succeeds with normal server-name verification.
- `crates/openshell-sandbox/src/main.rs` tests:
  - The new argument parses, is not supplied by an environment variable, and
    remains separate from all proxy flags.

**Automated commands and expected signals**

```shell
cargo test -p openshell-supervisor-network
cargo test -p openshell-supervisor-network --no-default-features
cargo test -p openshell-supervisor-process child_env
cargo test -p openshell-core grpc_client
cargo test -p openshell-sandbox
cargo fmt --all -- --check
```

Expected signals include both supervisor-network feature builds passing, strict
fixture failures being surfaced, and no regression in process/SSH child
environment tests.

**Automated and e2e verification (amended during implementation)**

Per explicit user direction on 2026-09-11, the former manual verification gate
is replaced by automated tests and the driver-backed e2e matrix in Slice 8.
Slice 2 exits on its shared-boundary automated checks: a real TLS fixture covers
matching-host success and hostname-mismatch rejection; staged-bundle tests cover
missing, malformed, private-key, and unusable material failing closed; the
real TLS/H2 two-CA fixture covers gateway trust isolation; and child trust-file
tests cover additive proxy and direct/process-only composition without setting
gateway mTLS trust.

The corresponding end-to-end behavior is not claimed complete in Slice 2.
Slice 8 must exercise it through the supported compute-driver lanes, including
private destination success, hostname rejection, invalid staged material,
gateway callback isolation, proxy/direct child trust behavior, and mount/path
inspection. No separate human manual verification remains for Slice 2.

**Failure, rollback, migration, and compatibility behavior**

- A present-but-invalid dedicated path fails the supervisor startup. A missing
  argument means legacy behavior, not an error.
- A no-setting launch has no new mount/argument and keeps current trust files.
- Reverting this slice is safe only with the driver slices reverted or with
  their no-argument path disabled; the fixed argument must not be left pointing
  at an unrecognized binary.
- No host trust store, gateway listener trust, OIDC trust, or policy semantics
  change.

**Observability and security**

The staged file is destination trust only. Keep separate constants and test
fixtures for it and for guest mTLS. Do not use `SSL_CERT_FILE` or the combined
child bundle when building gateway gRPC TLS. Retain normal rustls hostname and
chain validation.

**Dependencies**

Depends on slice 1's normalized-material shape but can use a temporary staged
fixture in unit tests. All driver adapters depend on this slice's argument,
path, and TLS API.

- [x] Slice 2 complete

### Slice 3 — Docker staging adapter

**Outcome and boundaries**

A Docker sandbox created with a configured global bundle has a read-only bind
mount at the common guest path and a dedicated supervisor argument. The
existing guest mTLS mounts, token mount, command, proxy settings, and user
configuration remain separate. With no bundle, the Docker create specification
has no new bind or argument.

**Files/components expected to change**

- `crates/openshell-server/src/compute/mod.rs` and the Docker branch in
  `src/compute/driver_config/builtin.rs`/`src/lib.rs`
  - Pass the startup bundle/artifact handle into the Docker constructor through
    the common build context.
- `crates/openshell-driver-docker/src/lib.rs`
  - Store the optional normalized host artifact path in the driver launch
    state.
  - Add a read-only bind for the fixed destination path and append the
    operator-owned supervisor argument to the generated command.
  - Fail sandbox creation if the gateway artifact is unavailable or the engine
    cannot create the required mount; do not omit the argument and continue.
  - Preserve the current gateway mTLS mount paths and environment variables.
- `crates/openshell-driver-docker/src/tests.rs` (and inline tests in `lib.rs`
  where existing test ownership requires)
  - Extend container-create fixtures and launch-spec helpers.

**Implementation notes and dependencies**

- Reuse the existing Docker bind/mount representation and host-path
  validation. The source is the gateway-owned normalized artifact, not any
  path from `additional_ca_cert_paths`.
- Mark the bind read-only and use a reserved destination path. Do not expose
  the CA through `ENV`, user command arguments, or a driver config key.
- Keep Docker's external/remote driver protocol unsupported when the global
  bundle is configured; the startup rejection from slice 1 must cover it.

**Tests to add or update**

- Configured Docker create body contains exactly one destination-trust bind,
  read-only, at the fixed path, and the dedicated argument.
- No-setting create body has no destination bind/argument and preserves the
  current gateway CA bind/`OPENSHELL_TLS_*` values.
- A user-supplied command/environment cannot replace the operator argument or
  destination mount.
- A missing artifact returns an actionable staging error without PEM data.
- Existing proxy and gateway TLS tests remain unchanged and pass.

**Automated commands and expected signals**

```shell
cargo test -p openshell-driver-docker
cargo test -p openshell-server compute::driver_config
cargo test -p openshell-server docker
cargo fmt --all -- --check
```

If a test filter does not match the existing module names, run the complete
package tests rather than weakening coverage. Expected signals are successful
mocked `ContainerCreateBody` assertions and no changes to no-setting snapshots.

**Automated and e2e verification (amended during implementation)**

Per explicit user direction on 2026-09-11, the former manual verification gate
is replaced by a Docker-backed e2e test. The wrapper generates an ephemeral
private CA and matching-host HTTPS fixture before gateway startup, configures
the global CA path, and runs a sandbox request through the real network
supervisor. The test must verify matching-host success, hostname-mismatch
rejection, and `docker inspect` evidence that the destination bind is read-only,
appears exactly once, carries the dedicated argument, and remains distinct from
the guest mTLS CA mount. The existing no-setting create-spec tests and the
standard Docker e2e lane retain coverage for omission/default behavior; no
separate human manual verification remains for Slice 3.

Command:

```shell
OPENSHELL_E2E_DOCKER_TEST=additional_ca e2e/rust/e2e-docker.sh
```

**Failure, rollback, migration, and compatibility behavior**

A failed bind or argument construction fails the sandbox operation before the
workload is ready. Removing the global section and restarting the gateway
restores the old create specification for new/restarted sandboxes. Existing
sandboxes retain their startup trust until restarted.

**Observability and security**

Report only the staging path category/count/digest if a launch diagnostic is
needed. Never log the mounted file. The destination CA must not be mounted at
`/etc/openshell/tls/client` or used for gateway callback authentication.

**Dependencies**

Depends on slices 1–2. Podman can reuse the test fixture shape but is a
separate adapter and must not be implemented as a Docker alias.

- [x] Slice 3 complete

### Slice 4 — Podman staging adapter

**Outcome and boundaries**

A Podman sandbox receives the same fixed destination path and dedicated
argument through a read-only bind. Existing `proxy_ca_bundle` handling keeps
its exact proxy pairing/validation semantics and is not reused as the global
setting. The unset path remains unchanged for rootful and rootless Podman.

**Files/components expected to change**

- `crates/openshell-server/src/compute/mod.rs`,
  `src/compute/driver_config/builtin.rs`, and the Podman factory path in
  `src/lib.rs`
  - Pass the shared bundle/artifact to Podman construction.
- `crates/openshell-driver-podman/src/driver.rs`
  - Store the optional artifact and append the common read-only mount and
    supervisor argument to the generated container specification.
  - Keep operator-owned proxy and gateway TLS arguments in their current
    distinct paths.
- `crates/openshell-driver-podman/src/container.rs`
  - Add the destination mount/command material to the existing Podman
    container launch builder without turning it into an environment setting.
- `crates/openshell-driver-podman/src/config.rs`
  - Do not add a driver-specific additional-CA key. Update validation only if
    needed to make the global startup handle visible to the runtime.
- `crates/openshell-driver-podman/README.md`
  - Update the proxy CA table/description to distinguish the new global
    destination setting from `proxy_ca_bundle`.

**Implementation notes and dependencies**

- Keep the existing `upstream_proxy_cli_args` helper and add a separate
  destination-trust argument helper so a future refactor cannot accidentally
  require an HTTPS proxy for a destination CA.
- Rootless Podman must use the same host-visible artifact assumptions already
  used by its TLS/proxy mounts. A permission or mount failure is fatal and
  actionable.
- Preserve current proxy-auth secrets and `OPENSHELL_PODMAN_TLS_*` handling.

**Tests to add or update**

- Configured/unconfigured Podman launch-spec tests for mount, read-only flag,
  fixed path, and dedicated argument.
- A regression test proving destination CA configuration does not satisfy or
  enable `proxy_ca_bundle` validation and does not make an `https_proxy`
  appear.
- Rootless and rootful command construction tests, plus existing proxy and
  mTLS mount tests.
- Missing artifact and user environment override failures.

**Automated commands and expected signals**

```shell
cargo test -p openshell-driver-podman
cargo test -p openshell-server compute::driver_config
cargo test -p openshell-server podman
cargo fmt --all -- --check
```

Expected signals are passing rootful/rootless spec tests and an unchanged
proxy-specific validation test, including the existing actionable
`proxy_ca_bundle is set but no https_proxy is configured` error.

**CI e2e verification (manual requirement waived)**

Per explicit user direction on 2026-09-11, no human confirmation is required.
The Podman e2e lane must run in CI with a private destination CA and inspect the
container mount/argv. It verifies private destination success, hostname
mismatch rejection, public destination success, and gateway callback success.
A proxy-only configuration independently confirms the old proxy path remains
separate.

**Failure, rollback, migration, and compatibility behavior**

If Podman cannot see the gateway artifact, sandbox creation fails rather than
launching without the configured trust. Removing the global setting restores
existing Podman specs and proxy behavior; no old driver key is migrated.

**Observability and security**

Do not put destination CA bytes in Podman environment or metadata. Keep it
read-only and separate from proxy credentials, proxy CA, and guest mTLS.

**Dependencies**

Depends on slices 1–2 and should follow slice 3 so both local-container
adapters can be compared against the same common contract.

- [x] Slice 4 complete

### Slice 5 — Kubernetes ConfigMap and topology adapters

**Outcome and boundaries**

Kubernetes sandboxes receive normalized destination CA data through one
OpenShell-managed `ConfigMap` per target namespace/gateway identity. The
combined topology mounts it only in the supervisor/agent container and passes
the common argument. The sidecar topology mounts it only in the network
sidecar and passes the argument there; the network-init and unrelated workload
containers do not receive it. Existing sidecar-generated child trust-file
handoff and guest mTLS mounts remain intact.

**Files/components expected to change**

- `crates/openshell-server/src/compute/mod.rs`,
  `src/compute/driver_config/builtin.rs`, and Kubernetes factory construction
  in `src/lib.rs`
  - Pass the shared normalized bytes and gateway identity into the Kubernetes
    adapter.
- `crates/openshell-driver-kubernetes/src/config.rs`
  - Add constants/types for the managed destination ConfigMap, its `ca.crt`
    key, stable name derivation, management label, fixed guest path, and
    topology-aware launch material. Do not add a user-facing driver TOML key.
- `crates/openshell-driver-kubernetes/src/driver.rs`
  - Create/apply/update the normalized `ConfigMap` before sandbox readiness,
    in the target namespace selected by shared/managed/operator workspace mode.
  - Extend `SandboxPodParams`, `sandbox_to_k8s_spec`, and
    `apply_supervisor_sidecar_topology` to add a read-only file mount and the
    dedicated argument in the correct supervisor container only.
  - Use server-side apply/update semantics and fail the sandbox operation on
    ConfigMap or pod-spec delivery errors.
  - Keep the ConfigMap bytes normalized gateway material; never read source
    paths from the pod and never mount the global CA into network-init or
    unrelated workload containers.
- Kubernetes driver tests colocated with `driver.rs`/`config.rs`
  - Cover shared, managed, and operator target namespace selection where those
    modes already have fixtures.

**Implementation notes and dependencies**

- The ConfigMap is public certificate data, not a Secret. It must have a
  stable gateway-derived name and OpenShell management label, and updates must
  replace the one object rather than create one per sandbox.
- Mount the ConfigMap key read-only at the common guest path (using the
  existing pod volume/subPath conventions as needed) and append the argument
  only to the combined supervisor or network sidecar command.
- In sidecar topology the network-init container must prepare nftables as it
  does now without the CA volume/argument. The process supervisor continues
  to consume the existing sidecar trust paths, which now include the
  additional material from slice 2.
- Preserve gateway mTLS ConfigMap/Secret paths and all sandbox JWT/config
  volumes. Do not use an ambient `SSL_CERT_FILE` in the pod spec.

**Tests to add or update**

- ConfigMap unit tests for normalized `ca.crt` bytes, stable name/labels,
  namespace selection, create/update behavior, and no object when the bundle is
  absent.
- Combined topology pod-spec tests for destination volume/mount/argument,
  existing guest mTLS material, and no mount in unrelated/init containers.
- Sidecar topology pod-spec tests for the same contract specifically on the
  network sidecar, with assertions that network-init and process/agent
  containers do not receive the destination mount/argument.
- Tests that a ConfigMap/API failure is surfaced before sandbox readiness and
  that an existing sandbox is not promised hot reload.
- Keep existing corporate-proxy and sidecar bootstrap tests passing.

**Automated commands and expected signals**

```shell
cargo test -p openshell-driver-kubernetes
cargo test -p openshell-server kubernetes
cargo fmt --all -- --check
```

Expected signals include both topology suites passing, exact container placement
assertions, no ConfigMap for the unset path, and no regression in proxy/JWT/TLS
volume tests.

**CI e2e verification (manual requirement waived)**

Automated CI e2e must create a private destination HTTPS fixture reachable by
the sandbox, configure the global bundle, and run one combined sandbox and one
sidecar sandbox. It must inspect the namespace ConfigMap and pod specs to prove
only the intended supervisor container has the read-only file and argument,
verify private destination success, hostname mismatch rejection, public trust,
and gateway callback isolation, and verify source/config updates do not affect
running supervisors until restart.

**Failure, rollback, migration, and compatibility behavior**

ConfigMap create/update or volume-spec failure prevents readiness and reports
the namespace/staging boundary without certificate content. Removing the
setting stops new mounts; existing pods retain startup trust until recreated.
Old Kubernetes workspaces with no global setting do not gain a ConfigMap.

**Observability and security**

Use namespace, ConfigMap identity, count, and digest in diagnostics; never log
`ca.crt`. Scope RBAC to only the ConfigMap operations required for the selected
workspace modes. Keep the destination file out of network-init and gateway
mTLS paths.

**Dependencies**

Depends on slices 1–2. Helm RBAC and source ConfigMap delivery are completed
in slice 7, but the driver must be testable with an in-process/fake Kubernetes
client before then.

- [x] Slice 5 complete

### Slice 6 — VM overlay and guest-init adapter

**Outcome and boundaries**

The VM driver stages normalized destination material inside each guest overlay
at the fixed path and causes the guest-init supervisor launch to receive the
same dedicated argument. It works for both supported VM launch backends. The
material is not passed as a guest environment variable or assumed to exist at
a host path inside the VM. Existing guest mTLS material and gateway endpoint
configuration remain independent.

**Files/components expected to change**

- `crates/openshell-server/src/compute/vm.rs`
  - Pass the gateway-owned artifact path/normalized material to the VM driver
    subprocess using an internal, operator-controlled launch option. Reject a
    configured bundle if the external VM driver contract cannot carry it.
- `crates/openshell-driver-vm/src/main.rs`
  - Parse the internal additional-bundle option and keep it distinct from
    user-facing guest environment/config values.
- `crates/openshell-driver-vm/src/driver.rs`
  - Read/validate the gateway artifact at sandbox preparation, copy normalized
    bytes into the per-sandbox overlay, and remove/update the reserved file
    when a restarted gateway has no/changed material.
  - Make overlay staging failure fatal before launch and preserve the existing
    gateway mTLS mounts/files.
- `crates/openshell-driver-vm/src/rootfs.rs`
  - Add the reserved-file write/remove operation used for fresh and preserved
    overlays, with read-only guest-file permissions and safe replacement.
- `crates/openshell-driver-vm/src/runtime.rs`
  - Thread the staging/launch metadata through both supported VM runtime
    backends without changing guest networking or callback trust.
- `crates/openshell-driver-vm/scripts/openshell-vm-sandbox-init.sh`
  - Append the dedicated supervisor argument only when the driver-owned overlay
    marker/file is present. Check the driver-owned overlay state so an image's
    unrelated file at the same path cannot activate the operator argument.

**Implementation notes and dependencies**

- The init script must not infer configuration from ordinary guest `ENV` or a
  file supplied solely by the image lower layer. A driver-owned marker or
  upper-overlay presence check is required.
- Preserve overlay behavior for `PreserveExisting`/restart paths: changed
  material replaces the old reserved file, and removed configuration removes
  the old file/marker so a previous CA is not silently retained.
- Validate again at the supervisor boundary from slice 2. The VM adapter's
  read/overlay validation is an earlier staging failure, not a trust-store
  replacement.

**Tests to add or update**

- VM driver/rootfs tests for configured bytes, fixed guest path, read-only
  permissions, atomic replacement, missing artifact, and removal on no-setting
  restart.
- Guest-init script tests for marker-present/absent argument generation and
  both runtime launch backends.
- Server-to-VM launch-config tests ensuring the additional option is present
  only when configured and never becomes `OPENSHELL_TLS_CA` or a guest env
  override.
- Existing overlay-preservation, callback mTLS, and VM startup tests remain
  green.

**Automated commands and expected signals**

```shell
cargo test -p openshell-driver-vm
cargo test -p openshell-server compute::vm
cargo fmt --all -- --check
```

Expected signals include overlay tests for fresh/preserved/reverted material,
script tests for both backend paths, and no changes to existing guest callback
TLS tests.

**CI e2e verification (manual requirement waived)**

Automated CI e2e must run `e2e/rust/e2e-vm.sh` with a private destination CA
and inspect the guest filesystem and supervisor command/serial log without
printing the certificate. It must verify private destination success, hostname
mismatch rejection, public trust, gateway callback isolation, and that
restart/removal updates or removes the reserved guest file only through the
normal sandbox restart lifecycle.

**Failure, rollback, migration, and compatibility behavior**

Any failure to read, copy, remove, or launch with the configured material
fails the VM sandbox operation. Removing the setting affects new/restarted
VMs; existing guests retain their startup trust. Reverting the driver removes
only the destination overlay file/argument and leaves existing guest mTLS
paths untouched.

**Observability and security**

VM serial/log diagnostics may identify the staging phase, certificate count,
and digest, but never PEM bytes. Keep the reserved path read-only and outside
user-controlled environment/configuration. Do not put destination roots in
the gateway callback trust file.

**Dependencies**

Depends on slices 1–2. It is independent of Docker/Podman/Kubernetes runtime
code but must use the same path/argument contract.

- [x] Slice 6 complete

### Slice 7 — Helm delivery and documentation

**Outcome and boundaries**

A Helm deployment can mount an operator-provided source ConfigMap key into the
gateway, render the global TOML section at the exact non-driver-specific
location, and grant only the Kubernetes ConfigMap permissions needed by the
selected workspace mode. Published and architecture documentation explains
source material, additive trust, topology delivery, startup lifecycle, and the
separation from proxy/gateway mTLS trust.

**Files/components expected to change**

- `deploy/helm/openshell/values.yaml`
  - Add a `supervisor.network` value for an existing operator-managed source
    ConfigMap name (key `ca.crt`), defaulting empty.
- `deploy/helm/openshell/templates/gateway-config.yaml`
  - Render `[openshell.supervisor.network]` and
    `additional_ca_cert_paths` only when the source ConfigMap value is set.
  - Keep the new section outside `[openshell.drivers.kubernetes]` and point it
    at the gateway's source mount path, not the sandbox fixed path.
- `deploy/helm/openshell/templates/_gateway-workload.tpl`
  - Add the read-only source ConfigMap volume/mount to the gateway workload.
  - Keep the existing `checksum/gateway-config` startup rollout behavior and
    document that out-of-band source ConfigMap changes require a gateway
    restart.
- `deploy/helm/openshell/templates/role.yaml`,
  `templates/clusterrole.yaml`, and any corresponding RBAC helper
  - Add narrowly scoped ConfigMap get/create/patch permissions for shared and
    managed/operator target namespaces, gated consistently with the chart's
    enabled global bundle setting.
- `deploy/helm/openshell/tests/gateway_config_test.yaml` and
  `tests/clusterrole_test.yaml` (plus a new focused test file if the existing
  suites cannot express the topology)
  - Assert global TOML placement, source mount/key, absent-value omission, and
    workspace-mode RBAC.
- `deploy/helm/openshell/README.md`
  - Regenerate/update Helm values documentation and source ConfigMap example.
- `docs/reference/gateway-config.mdx`
  - Document the exact TOML schema, PEM-only/path semantics, validation/error
    behavior, additive roots, restart lifecycle, and proxy/gateway mTLS
    distinction.
- `architecture/sandbox.md`
  - Update the stable data/control-flow description for gateway normalization,
    local/ConfigMap/VM staging, combined/sidecar placement, and trust-domain
    separation.
- `rfc/0003-gateway-configuration/README.md`
  - Add the global supervisor-network schema to the canonical configuration
    reference if this RFC remains the schema source.
- Driver READMEs that describe the proxy-only CA path, at minimum
  `crates/openshell-driver-podman/README.md` and any affected Docker,
  Kubernetes, or VM table sections.

**Implementation notes and dependencies**

- The source ConfigMap mounted into the gateway is operator-owned and contains
  `ca.crt`; the Kubernetes compute driver later creates its own managed
  per-target-namespace ConfigMap from normalized bytes. Do not conflate those
  two objects.
- The chart must never render the new list under a driver table. An empty
  value must render neither the TOML section nor a source volume.
- RBAC should authorize only the operations needed for the managed destination
  ConfigMap. If a manually authored TOML enables the feature while the Helm
  value is empty, document that the operator must provide equivalent RBAC.
- Keep docs active, concise, and explicit that private keys, DER-only input,
  inline PEM, URLs, hot reload, and custom/remote driver propagation are not
  supported.

**Tests to add or update**

- Helm render with source ConfigMap configured: inspect the gateway TOML,
  source mount/key, rollout checksum, and shared/managed/operator RBAC.
- Helm render with default values: assert no new section, mount, or
  destination ConfigMap permissions.
- Assert the field is absent from rendered `[openshell.drivers.kubernetes]`.
- Markdown/reference checks for exact path and argument names and for the
  destination/control-plane/proxy distinction.

**Automated commands and expected signals**

```shell
helm lint deploy/helm/openshell
helm template openshell deploy/helm/openshell --set agentSandbox.preflight.enabled=false
helm unittest deploy/helm/openshell
cargo fmt --all -- --check
```

If the repository's Helm test plugin is unavailable, run the repository's
configured chart-test task or render each relevant values fixture and inspect
its YAML/TOML assertions. Expected signals are no new default resources and
valid YAML/RBAC for every supported workspace mode.

**CI integration verification (manual requirement waived)**

Automated CI coverage must:

1. Create a source ConfigMap with `ca.crt`, render/install the chart, and prove
   the gateway sees the configured source path.
2. Prove a chart upgrade changes the gateway workload when rendered TOML
   changes and that changing only source ConfigMap content requires a gateway
   restart.
3. Inspect rendered/live namespace RBAC to prove the driver-managed destination
   ConfigMap is permitted only where the selected workspace mode needs it.

**Failure, rollback, migration, and compatibility behavior**

A missing source ConfigMap or unreadable mounted key causes gateway startup
failure with the global field/path error. Default chart values produce the
existing workload/configuration. Removing the value and restarting rolls back
new trust delivery; existing sandboxes still require the documented restart.
No existing proxy or gateway TLS values are renamed.

**Observability and security**

Document certificate scope and the risk that every policy-permitted endpoint
signed by a configured CA becomes trustable. Do not show PEM data in Helm test
output, docs examples, or logs. Preserve least-privilege RBAC and distinct
source/destination/control-plane paths.

**Dependencies**

Depends on the config contract (slice 1) and Kubernetes adapter names/paths
(slice 5). Documentation can describe the VM/local adapters after their
contracts are implemented.

- [x] Slice 7 complete

### Slice 8 — Cross-driver regression, e2e, and final hardening

**Outcome and boundaries**

The complete feature is verified as one gateway-to-supervisor contract across
Docker, Podman, Kubernetes combined/sidecar, and VM. The final checks cover
private destination success, hostname enforcement, public-root compatibility,
control-plane isolation, invalid-material fail-closed behavior, removal/restart
lifecycle, and unsupported remote/custom drivers.

**Files/components expected to change**

- `e2e/support/gateway-common.sh`
  - Add a reusable, ephemeral destination-CA/server fixture and redacted
    configuration helper if the existing e2e harness can host it safely.
- `e2e/with-docker-gateway.sh`, `e2e/with-podman-gateway.sh`,
  `e2e/with-kube-gateway.sh`, and `e2e/rust/e2e-vm.sh`
  - Add opt-in setup for the global source path/configuration and fixture
    reachability, preserving each lane's existing default configuration.
- `e2e/rust/Cargo.toml` and a focused
  `e2e/rust/tests/additional_ca.rs` (or the closest existing TLS e2e test)
  - Exercise a configured private destination and negative hostname case for
    each lane that can provision the fixture. Skip only when the lane does not
    own a gateway/fixture, and retain unit/contract coverage for every lane.
- Existing relevant driver tests/scripts touched by discovered integration
  gaps, without adding a new protocol or changing unrelated e2e defaults.

**Implementation notes and dependencies**

- Reuse one generated CA/server fixture and one test flow; do not duplicate
  independent TLS implementations for each driver. The fixture must use a
  certificate SAN matching the requested hostname so a successful test proves
  hostname verification is still active.
- Run the live test separately for Docker, Podman, Kubernetes combined,
  Kubernetes sidecar, and VM where the local environment supports each lane.
  External/custom-driver lanes must instead assert an early unsupported-driver
  startup error when the global setting is present.
- Exercise both proxy/direct child trust where the existing lane can do so;
  do not turn a proxy-only fixture into evidence for the global destination
  setting.

**Tests to add or update**

- Full cross-package unit tests from slices 1–7.
- Live private-CA path success and hostname-mismatch failure for all supported
  in-tree drivers/topologies that the e2e environment can run.
- No-setting smoke/regression for each lane to prove public/default trust and
  gateway callback behavior remain intact.
- Gateway startup invalid-file test and staged-file replacement/removal test.
- Remote/custom driver rejection test with a configured global bundle.
- Verify no generated logs, test artifacts, Helm output, or failure messages
  contain certificate/private-key contents.

**Automated commands and expected signals**

```shell
mise run pre-commit
mise run test
mise run e2e
# Targeted Rust e2e lanes when their prerequisites are available:
cd e2e/rust && cargo test --features e2e-docker --test additional_ca
cd e2e/rust && cargo test --features e2e-podman --test additional_ca
cd e2e/rust && cargo test --features e2e-kubernetes --test additional_ca
cd e2e/rust && cargo test --features e2e-vm --test additional_ca
```

Use the repository's lane wrappers (`e2e/with-docker-gateway.sh`,
`e2e/with-podman-gateway.sh`, `e2e/with-kube-gateway.sh`, and
`e2e/rust/e2e-vm.sh`) rather than bypassing their gateway/fixture setup.
Expected signals are all applicable lanes passing, unsupported lanes failing
before connection, and no-setting lanes retaining current smoke behavior.

**CI e2e matrix (manual requirements waived)**

Per explicit user direction on 2026-09-11, every row below is an automated CI
requirement rather than a human verification gate:

| Scenario | Docker | Podman | K8s combined | K8s sidecar | VM |
| --- | --- | --- | --- | --- | --- |
| Private destination signed by configured CA succeeds | [ ] | [ ] | [ ] | [ ] | [ ] |
| Hostname mismatch is rejected | [ ] | [ ] | [ ] | [ ] | [ ] |
| Public/default destination remains trusted | [ ] | [ ] | [ ] | [ ] | [ ] |
| Gateway callback still trusts only gateway CA | [ ] | [ ] | [ ] | [ ] | [ ] |
| Invalid source/staged material fails closed | [ ] | [ ] | [ ] | [ ] | [ ] |
| Remove config + restart removes new trust for new sandboxes | [ ] | [ ] | [ ] | [ ] | [ ] |
| No-setting behavior is unchanged | [ ] | [ ] | [ ] | [ ] | [ ] |

CI assertions must also inspect Docker/Podman mounts, Kubernetes ConfigMap/pod
placement, VM overlay contents, and representative logs for
secret/certificate disclosure. A lane may be unavailable locally, but it must
not be waived from the applicable CI matrix.

**Failure, rollback, migration, and compatibility behavior**

Any failed final check blocks completion. Roll back by removing the global
section/chart value and restarting the gateway plus affected sandboxes; do not
silently downgrade an invalid configured bundle. Existing proxy-specific
configuration and public-root behavior are the compatibility baseline.

**Observability and security**

Before completion, audit all new log/error paths and test artifacts for PEM
content, confirm OCSF events are appropriate configuration-state events, and
confirm the control-plane two-CA test remains structural rather than relying
only on hostname exclusion.

**Dependencies**

Depends on all prior slices. This slice is verification/hardening, not a place
to introduce new design decisions; any change to configuration shape,
propagation contract, trust scope, or unsupported-driver policy returns to the
design/outline gate.

- [ ] Slice 8 complete

## Deliberately not being changed

- No protobuf, public compute-driver RPC, SDK, or CLI user-facing flag for the
  gateway setting.
- No field in `[openshell.drivers.docker]`, `[openshell.drivers.podman]`,
  `[openshell.drivers.kubernetes]`, or `[openshell.drivers.vm]`.
- No change to `proxy_ca_bundle` meaning, proxy pairing validation, proxy
  credentials, or proxy routing.
- No merge with gateway listener TLS, OIDC CA, middleware/interceptor TLS,
  guest mTLS, `OPENSHELL_TLS_CA`, or any other control-plane trust material.
- No replacement of Mozilla/system/native roots, no disabled hostname
  verification, no permissive/self-signed-leaf mode, and no host trust-store
  mutation.
- No inline PEM, DER-only input, private-key acceptance, URL download, or
  per-sandbox/per-policy CA selector.
- No hot reload or promise that an existing running supervisor observes a
  ConfigMap/source-file update.
- No propagation contract for remote/custom compute drivers; configured material
  must cause an explicit unsupported-driver error instead of being ignored.
- No unrelated architecture, policy, network socket, or sandbox lifecycle
  refactor.

## Order rationale, likely deviations, and approval checklist

The order establishes the data/error contract first, then the one common
supervisor consumer, then independently testable driver adapters. Docker and
Podman are separated because their host-engine mount/command APIs and proxy
configuration differ. Kubernetes follows with its ConfigMap and topology
matrix. VM follows with its distinct overlay/init lifecycle. Helm/docs come
after the runtime names are stable, and the final slice exercises the whole
contract without hiding adapter-specific failures behind one live test.

Expected implementation details that may be refined without reopening the
design are the exact gateway state subdirectory/artifact filename, the stable
Kubernetes ConfigMap name derivation, the Helm value key spelling, and whether
an existing e2e TLS fixture can be extended instead of adding
`additional_ca.rs`. Such refinements must preserve the fixed guest path,
argument, global TOML placement, strict validation, topology placement, and
control-plane isolation. A change to any of those invariants requires a design
revision and a new approval.

Before outline approval, review:

- [ ] Slice order and dependencies are acceptable.
- [ ] The shared path/argument and no-setting behavior are explicit.
- [ ] All five required runtime paths (Docker, Podman, Kubernetes combined,
      Kubernetes sidecar, VM) have independent automated and CI e2e checks.
- [ ] Invalid material, unsupported drivers, restart/removal, hostname
      verification, and two-CA control-plane isolation are covered.
- [ ] Helm/RBAC and architecture/reference documentation scope is complete.
- [ ] The final verification commands are available in the target environment.

After explicit approval, update this document's `document_status` to
`approved`, set `state.json.approvals.outline` to `true`, move the task to the
`implementation` phase, and set `current_slice` to `1`. Until then, leave this
file and `state.json` in the draft/outline state and do not edit implementation
files.
