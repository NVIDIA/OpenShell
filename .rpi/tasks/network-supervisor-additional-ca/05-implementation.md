---
rpi_task: network-supervisor-additional-ca
workflow: rpi
phase: implementation
document_status: active
updated: 2026-09-11T20:08:25Z
current_slice: 8
---

# Implementation log

## Slice 1 — Global configuration and startup material contract

### Status

Complete. On 2026-09-11 the user explicitly directed that the startup behavior
be exercised by an automated end-to-end-style test instead of manual
verification. The outline was amended accordingly, the real gateway binary
process test passes, and the Slice 1 checkbox is complete.

Work is in the dedicated worktree and branch:

- `/home/jjaggars/.worktrees/OpenShell/feat-network-supervisor-additional-ca`
- `feat/network-supervisor-additional-ca`

### Implemented behavior

- Added global `[openshell.supervisor.network]` configuration with an ordered
  `additional_ca_cert_paths` list. The section is outside all
  `[openshell.drivers.*]` tables, denies unknown keys, defaults to no paths,
  and rejects empty path entries.
- Added `openshell-core::NetworkSupervisorTrustBundle` with read-only accessors
  for canonical PEM, certificate count, non-secret SHA-256 digest, and the
  gateway-owned artifact path. Its `Debug` implementation omits PEM bytes.
- Added gateway startup normalization in
  `crates/openshell-server/src/network_trust.rs`:
  - reads every configured source path before compute-driver startup;
  - rejects unreadable, empty, certificate-free, malformed, non-certificate,
    private-key, mixed, and unusable-certificate content;
  - rejects unrelated text mixed with PEM blocks instead of accepting a valid
    subset;
  - canonicalizes all certificate blocks and computes a digest after
    normalization;
  - writes one gateway-owned artifact atomically under the OpenShell state
    directory with local-engine-readable permissions;
  - keeps source paths only in actionable errors and never includes certificate
    material in diagnostics or `Debug` output.
- Carries the optional bundle through `ServerStartupConfig`,
  `DriverStartupContext`, and the common `ComputeDriverBuildContext` accessor.
  The existing gateway mTLS paths remain separate.
- Rejects a configured bundle before remote endpoint connection or unsupported
  custom-driver construction. The four accepted driver names are Docker,
  Podman, Kubernetes, and VM. Existing no-bundle remote/custom behavior is
  unchanged.

### Files changed

- `crates/openshell-core/src/lib.rs`
- `crates/openshell-core/src/network_trust.rs`
- `crates/openshell-server/src/config_file.rs`
- `crates/openshell-server/src/network_trust.rs`
- `crates/openshell-server/src/cli.rs`
- `crates/openshell-server/src/lib.rs`
- `crates/openshell-server/src/compute/driver_config.rs`
- `crates/openshell-server/src/compute/driver_config/builtin.rs`
- `crates/openshell-gateway/Cargo.toml`
- `crates/openshell-gateway/tests/network_trust_startup.rs`
- `Cargo.lock`
- `crates/openshell-supervisor-process/src/sandbox/linux/landlock.rs`
  (unrelated formatting-only cleanup approved by the user)

### Automated verification

Passed:

- `cargo test -p openshell-core network_trust` — 2 tests passed.
- `cargo test -p openshell-server config_file` — 33 tests passed.
- `cargo test -p openshell-server network_trust` — 15 tests passed, including
  startup normalization, redaction, invalid-material, context propagation,
  remote endpoint, unknown remote, and unsupported custom-driver tests.
- `cargo test -p openshell-server driver_config` — 16 tests passed, including
  rejection of the global field in a Docker driver table.
- `cargo test -p openshell-server configured_compute_driver` — 8 existing
  no-setting driver-selection tests passed.
- `cargo check -p openshell-server --no-default-features` — passed.
- Targeted `rustfmt --edition 2024 --check` over all changed Rust files —
  passed.
- `git diff --check` — passed.
- `cargo test -p openshell-gateway --no-default-features --test network_trust_startup`
  — 3 process-level tests passed. They launch the real gateway binary and cover
  redacted valid-bundle metadata, missing/empty/private-key startup failures,
  unsupported custom-driver rejection, and remote-endpoint rejection before a
  socket connection or remote-driver construction.

The first process-test run exposed assertions that did not account for miette's
line wrapping and tracing ANSI formatting. The test now strips ANSI safely,
normalizes diagnostic whitespace, and checks generated PEM payload markers
rather than relying on full multiline string matching. The implementation
behavior did not fail during this adjustment.

The first focused run exposed that a configured bundle still allowed a built-in
name with an endpoint override to become `Remote`; the resolution path now
rejects that combination before the remote connection path. The final focused
runs above pass.

The required repository-wide check:

- `mise exec -- cargo fmt --all -- --check` — passed after the user approved
  incorporating the formatter's line-wrapping change in the previously
  unrelated `crates/openshell-supervisor-process/src/sandbox/linux/landlock.rs`.
  This was formatting-only and did not alter Landlock behavior.

Additional diagnostics:

- `cargo test -p openshell-server --no-default-features network_trust` reaches
  unrelated existing test references to the optional
  `openshell_driver_kubernetes` crate and fails to compile those tests. The
  non-test `cargo check -p openshell-server --no-default-features` passes.
- On 2026-09-11, `git diff --check` passed and
  `mise exec -- cargo fmt --all -- --check` reproduced the same sole formatting
  difference at
  `crates/openshell-supervisor-process/src/sandbox/linux/landlock.rs:124`.
  Plain `cargo fmt` was unavailable because `cargo` is not directly on this
  session's `PATH`; `mise exec` resolved the repository toolchain correctly.
- On 2026-09-11, after the user approved incorporating the formatting cleanup,
  `mise exec -- cargo fmt --all -- --check` and `git diff --check` both passed.

### Manual verification status

Not required for Slice 1 after the user explicitly replaced the manual startup
check with automated process-level verification on 2026-09-11. This is not a
claim that a human performed the old steps. Live destination TLS behavior and
the cross-driver matrix remain scheduled for Slice 8.

### Deviations, risks, and follow-ups

- The approved outline is marked `document_status: approved` and
  `state.json.approvals.outline` is `true`, while prose at the end of the
  outline still contains stale pre-approval instructions saying it is a draft.
  The current state and explicit implementation request were followed; the
  stale prose was not rewritten during implementation.
- Driver adapters and supervisor TLS consumption are deliberately not changed
  in this slice. They are the next approved slices and must consume the fixed
  bundle/path/argument contract from this slice.
- With user approval, the pre-existing Landlock formatting difference was
  incorporated as a formatting-only deviation so the repository-wide format
  check passes. No behavioral Landlock change was made.
- The approved outline's original Slice 1 manual verification was amended by
  explicit user direction to an automated process-level gateway test. No human
  execution of the superseded steps is claimed.
- No commit or push was made.

## Slice 2 — Common supervisor TLS and child trust behavior

### Status

Complete on 2026-09-11. Implementation and the approved shared-boundary
automated checks pass. Per explicit user direction, the former manual
verification gate is replaced by automated coverage and the driver-backed e2e
matrix in Slice 8. The Slice 2 checkbox is complete and task state advances to
Slice 3.

### Implemented behavior

- Added the reserved guest path
  `NETWORK_ADDITIONAL_CA_BUNDLE_PATH` at
  `/etc/openshell-tls/network-additional-ca.crt`, documented as distinct from
  gateway client mTLS and corporate-proxy trust paths.
- Added the operator-only `--network-additional-ca-bundle` supervisor argument
  with no environment alias and threaded it explicitly through `run_sandbox`
  into `run_networking`.
- The network supervisor now validates and canonicalizes the staged bundle
  before starting networking tasks. Missing, empty, malformed, non-certificate,
  mixed certificate/private-key, and unusable material fails startup rather
  than falling back to default roots.
- Upstream rustls configuration now augments the feature-selected default
  roots with the explicit destination bundle in both bundled-root and
  native-root builds. Normal rustls chain and hostname verification remains in
  place.
- Child trust files now support both proxy mode and additional-only/direct
  mode. The standalone file contains configured destination roots plus the
  generated OpenShell interception CA when present; the combined file contains
  system roots, configured destination roots, and the interception CA when
  present. With no additional setting, the existing proxy-mode output bytes
  are unchanged.
- Existing upstream-proxy CA parsing and pairing remain separate. The
  native-root build now overlays the explicitly supplied system/proxy bundle
  after native roots; this was required for the existing corporate-proxy and
  validated-upstream TLS tests to pass in the outline-mandated
  `--no-default-features` build.
- Existing process and SSH paths continue to consume the generated standalone
  and combined child files. A focused assertion confirms those variables do
  not set `OPENSHELL_TLS_CA` or use the gateway mTLS CA mount.
- Refactored gateway gRPC TLS construction without changing its inputs: it
  still trusts only `OPENSHELL_TLS_CA` and the explicit client identity. A
  two-CA TLS/H2 test proves a destination-CA-signed fake gateway is rejected,
  the configured gateway CA succeeds, and server-name mismatch remains fatal.
- Added an OCSF configuration-state success event when additional destination
  trust is initialized; it contains no certificate data.

### Files changed

- `crates/openshell-core/Cargo.toml`
- `crates/openshell-core/src/container_paths.rs`
- `crates/openshell-core/src/grpc_client.rs`
- `crates/openshell-sandbox/src/lib.rs`
- `crates/openshell-sandbox/src/main.rs`
- `crates/openshell-supervisor-network/src/l7/tls.rs`
- `crates/openshell-supervisor-network/src/run.rs`
- `crates/openshell-supervisor-process/src/child_env.rs`
- `Cargo.lock` (test dependency metadata)

No `sidecar_control.rs`, process-launch, or SSH-launch behavior needed a code
change: the existing sidecar bootstrap already transfers the generated
standalone/combined path pair, and all process/SSH call sites already consume
that pair through `child_env::tls_env_vars`.

### Automated verification

Passed the exact checks from the approved outline:

- `mise exec -- cargo test -p openshell-supervisor-network` — 1,237 unit tests
  passed, 2 ignored; integration tests passed, with 5 LocalStack-dependent
  tests ignored.
- `mise exec -- cargo test -p openshell-supervisor-network --no-default-features`
  — 1,237 unit tests passed, 2 ignored; integration tests passed, with 5
  LocalStack-dependent tests ignored.
- `mise exec -- cargo test -p openshell-supervisor-process child_env` — 2 tests
  passed.
- `mise exec -- cargo test -p openshell-core grpc_client` — 13 tests passed,
  including destination/gateway CA isolation and hostname verification.
- `mise exec -- cargo test -p openshell-sandbox` — 130 tests passed across the
  library, binary, and startup logging integration test.
- `mise exec -- cargo fmt --all -- --check` — passed.

Additional checks:

- `git diff --check` — passed.
- `mise exec -- cargo clippy -p openshell-core -p openshell-supervisor-network --tests -- -D warnings`
  — passed.
- A broader four-package Clippy diagnostic reached pre-existing warnings in
  `crates/openshell-supervisor-process/src/sandbox/linux/landlock.rs`; the two
  Slice 2 test-code warnings found in the same run were fixed. The unrelated
  Landlock warnings were not changed.

The first native-root full test run exposed that the old
`build_upstream_client_config` ignored its explicit PEM overlay when
`bundled-ca-roots` was disabled, causing two existing corporate-proxy/upstream
TLS tests to fail with `UnknownIssuer`. The native path now retains native roots
and adds the explicit overlay. Both focused regressions and the final complete
no-default-feature suite pass.

### E2E verification status

On 2026-09-11 the user explicitly directed that the former manual checks be
validated by e2e tests instead of human review. The shared Slice 2 contracts are
covered by the passing automated TLS, staged-file, two-CA gateway-isolation,
and child trust-file tests recorded above. True driver-backed end-to-end
validation remains assigned to Slice 8, after slices 3–7 provide staging for
Docker, Podman, Kubernetes, and VM.

This slice does not claim that the final e2e matrix has already run. Slice 8
must cover matching-host private destination success, hostname rejection,
invalid staged material failing closed, destination/gateway trust isolation,
and additive proxy/direct child trust behavior in the applicable driver lanes.
No separate human manual verification remains for Slice 2.

### Deviations, risks, and follow-ups

- The implementation adds `h2` and `tokio-rustls` as test-only dependencies of
  `openshell-core` for the real TLS/H2 gateway isolation fixture; production
  dependency behavior is unchanged.
- Native-root upstream construction now overlays the explicit
  `system_ca_bundle` after loading native roots. This is a narrow compatibility
  correction needed to keep the existing proxy-specific CA behavior working
  in the required no-default-feature test lane; it does not merge proxy and
  destination configuration meanings.
- Driver staging is intentionally not part of this slice. Until slices 3–6,
  no compute driver mounts the fixed path or emits the dedicated argument.
- Per explicit user direction, the former Slice 2 manual gate was reassigned to
  automated shared-boundary tests plus Slice 8's driver-backed e2e matrix. This
  advances implementation dependencies without claiming the final e2e matrix
  has run.
- No commit or push was made.

## Slice 3 — Docker staging adapter

### Status

Complete on 2026-09-11 under an explicit user-approved CI verification
deferral. Driver implementation and package-level automated verification pass.
The Docker-backed e2e test and wrapper support are implemented and compile, but
the local environment does not have the `docker` CLI. At 2026-09-11T13:44:58Z
the user explicitly directed that Docker not be installed on this machine and
that the live Docker e2e be left to CI. Slice 3 is complete for implementation
sequencing, without claiming that the live e2e has passed.

### Implemented behavior

- The in-process Docker factory now passes the gateway-owned normalized artifact
  path from `ComputeDriverBuildContext::network_trust_bundle()` into the Docker
  constructor. The standalone Docker driver passes no bundle, consistent with
  Slice 1's rejection of remote/external delivery when the global setting is
  configured.
- Docker launch state stores only the optional gateway-owned artifact path. It
  does not add a Docker driver configuration key or expose certificate material
  through sandbox environment variables.
- Configured container create bodies include exactly one `ro,z` bind from the
  gateway artifact to
  `/etc/openshell-tls/network-additional-ca.crt` and append the dedicated
  `--network-additional-ca-bundle` argument with that fixed guest path.
- The operator bind checks that the artifact source is absolute and still a
  regular file each time a container specification is built. A missing or
  unusable source fails sandbox provisioning before the Docker create call;
  Docker mount failure remains fatal through the existing create error path.
- The unset path emits no new bind or argument. Existing guest mTLS mounts,
  `OPENSHELL_TLS_*` values, proxy arguments, token mount, supervisor entrypoint,
  and workspace command construction remain separate.
- Existing reserved-control-path validation prevents user bind/volume/image
  mounts from masking the destination path. Tests also prove user command and
  environment inputs cannot replace the operator-owned argument.

### Files changed

- `crates/openshell-driver-docker/src/lib.rs`
- `crates/openshell-driver-docker/src/main.rs`
- `crates/openshell-driver-docker/src/tests.rs`
- `crates/openshell-gateway/src/lib.rs`
- `e2e/with-docker-gateway.sh`
- `e2e/rust/e2e-docker.sh`
- `e2e/rust/Cargo.toml`
- `e2e/rust/tests/additional_ca.rs`

No change was needed in `crates/openshell-server/src/compute/mod.rs`: Slice 1
already exposed the bundle through the common build context used by the actual
Docker factory in `crates/openshell-gateway/src/lib.rs`.

### Automated verification

Passed:

- `mise exec -- cargo test -p openshell-driver-docker` — 163 unit tests passed,
  including configured/unconfigured create bodies, one fixed read-only bind,
  dedicated argv, missing-artifact failure, and user override resistance.
- `mise exec -- cargo test -p openshell-server compute::driver_config` — 14
  focused tests passed.
- `mise exec -- cargo test -p openshell-server docker` — the requested filter
  matched no server tests, so the complete package suite was run as required by
  the outline rather than treating an empty filter as coverage.
- `mise exec -- cargo test -p openshell-server` — 1,531 library tests passed
  with 8 pre-existing flaky tests ignored; all integration suites passed.
- `mise exec -- cargo fmt --all -- --check` — passed.
- `mise exec -- cargo check -p openshell-gateway` — passed, verifying the
  gateway factory-to-Docker constructor propagation path.
- `git diff --check` — passed.
- `bash -n e2e/with-docker-gateway.sh` — passed.
- `mise exec -- cargo test --manifest-path e2e/rust/Cargo.toml --features e2e-docker --test additional_ca --no-run`
  — passed; the focused e2e binary compiles.
- `mise exec -- cargo clippy --manifest-path e2e/rust/Cargo.toml --features e2e-docker --test additional_ca -- -D warnings`
  — passed.
- `mise exec -- cargo fmt --manifest-path e2e/rust/Cargo.toml -- --check` —
  passed after formatting the new test.
- `mise exec -- cargo fmt --all -- --check` — passed.
- A temporary execution of the wrapper's OpenSSL certificate-generation steps,
  followed by `openssl verify` and SAN inspection — passed; the leaf chains to
  the generated CA and contains only `DNS:host.openshell.internal`.

Not run:

- `OPENSHELL_E2E_DOCKER_TEST=additional_ca e2e/rust/e2e-docker.sh` — blocked
  because this environment has no `docker` CLI and cannot reach a Docker
  daemon.
- `shellcheck e2e/with-docker-gateway.sh` — unavailable because `shellcheck` is
  not installed; `bash -n` passes.

Latest infrastructure probe:

- `docker info` at 2026-09-11T13:43:47Z — exited 127 with
  `/bin/bash: docker: command not found`. The focused e2e command was not
  started because its wrapper has the same Docker CLI/daemon prerequisite.
  Reproduction: `docker info`, then
  `OPENSHELL_E2E_DOCKER_TEST=additional_ca e2e/rust/e2e-docker.sh` once Docker
  is available.

The first Docker test run exposed that the generic user-mount helper correctly
rejects the reserved guest path and therefore cannot construct an internal
OpenShell bind. The destination bind now reuses the existing absolute-source
validation and missing-file behavior while constructing only the fixed
operator-owned target. The final complete Docker suite passes.

### E2E verification status

No manual verification is required after the user's explicit 2026-09-11
direction to automate the gate. The new focused Docker e2e path:

1. generates an ephemeral private CA and a CA-signed HTTPS leaf whose SAN is
   `host.openshell.internal` before gateway startup;
2. renders the global `[openshell.supervisor.network]` path into the managed
   Docker gateway configuration;
3. verifies a sandbox request to the matching hostname succeeds without
   disabling TLS verification;
4. verifies the same server reached through `host.docker.internal` is rejected
   for hostname mismatch; and
5. inspects the live Docker container for exactly one read-only destination
   bind, the dedicated supervisor argument, and separation from the guest mTLS
   CA mount.

The standard Docker wrapper remains unchanged unless the focused test is
selected, so ordinary no-setting e2e runs preserve the default path. The live
focused command is deferred to CI by explicit user direction because Docker is
unavailable in this environment. No local or CI e2e pass is claimed in this
log. The deferral allows implementation sequencing to continue to Slice 4; a
failure in CI remains a blocking Slice 3 regression that must be fixed before
final validation.

### Deviations, risks, and follow-ups

- The actual first-party Docker factory lives in
  `crates/openshell-gateway/src/lib.rs`, not the outline's stale suggested
  `openshell-server` Docker branch path. The change follows the existing
  factory boundary and uses the already-approved common context accessor.
- `crates/openshell-driver-docker/src/main.rs` was updated only for the
  constructor's new optional startup argument; standalone mode supplies
  `None` and retains its previous behavior.
- The existence check and Docker create are necessarily separate operations.
  If the gateway artifact changes after specification construction, Docker's
  required bind still fails the create operation rather than launching without
  the argument.
- Live TLS behavior is not inferred from create-body tests or compile-only e2e
  checks. By explicit user direction it remains pending in CI on the focused
  Docker e2e command and is also part of Slice 8's cross-driver matrix.
- The e2e wrapper enables the fixture only when
  `OPENSHELL_E2E_DOCKER_TEST=additional_ca`; existing endpoint-mode and external
  compute-driver runs reject the incompatible fixture mode instead of silently
  ignoring the configured bundle.
- The generated private key and certificate material live only in the wrapper's
  temporary directory and are removed by its existing cleanup trap. Test output
  contains only the fixture marker, paths/categories, and Docker metadata—not
  PEM or key bytes.
- No commit or push was made.

## Slice 4 — Podman staging adapter

### Status

Complete on 2026-09-11. Implementation and automated checks pass. The live
rootless Podman e2e passed private destination trust, hostname-mismatch
rejection, public-root trust, gateway callback trust, and read-only mount/argv
inspection; the existing proxy-only Podman suite also passed independently.
At 2026-09-11T17:38:10Z the user explicitly waived all manual testing gates and
directed that these scenarios be implemented as e2e tests that run in CI. The
Slice 4 checkbox is complete and task state advances to Slice 5.

### Implemented behavior

- The in-process Podman factory passes the gateway-owned normalized artifact
  path from `ComputeDriverBuildContext::network_trust_bundle()` into the Podman
  constructor. The standalone Podman driver passes `None`, consistent with the
  existing rejection of global destination trust for external drivers.
- `PodmanComputeDriver` stores only the optional gateway-owned artifact path
  and reports only configured presence in `Debug`; it does not add certificate
  bytes or a Podman driver configuration key.
- Configured Podman container specs contain exactly one read-only bind at
  `/etc/openshell-tls/network-additional-ca.crt` and one dedicated
  `--network-additional-ca-bundle` argument with that fixed guest path.
- Spec construction revalidates that the gateway artifact source is an
  absolute UTF-8 path to a regular file. A missing or unusable artifact fails
  staging with an actionable error and no certificate content.
- Destination trust has a separate argv helper and mount path from
  `proxy_ca_bundle`. It neither creates an `https_proxy` nor satisfies the
  existing proxy pairing validation. Proxy CA, proxy credentials, guest mTLS,
  supervisor delivery, and user mounts retain their existing paths.
- The unset path emits no destination mount or argument. Tests cover both the
  default/rootful spec shape and `userns = "auto"` rootless spec shape.
- Sandbox command/environment inputs cannot replace the operator argument, and
  reserved-path validation rejects a user mount targeting the fixed
  destination path.
- The Podman README now identifies the global setting and distinguishes it
  from both `proxy_ca_bundle` and gateway callback mTLS.

### Files changed

- `crates/openshell-gateway/src/lib.rs`
- `crates/openshell-driver-podman/src/driver.rs`
- `crates/openshell-driver-podman/src/container.rs`
- `crates/openshell-driver-podman/src/config.rs`
- `crates/openshell-driver-podman/src/main.rs`
- `crates/openshell-driver-podman/README.md`
- `e2e/with-podman-gateway.sh`
- `e2e/rust/e2e-podman.sh`
- `e2e/rust/Cargo.toml`
- `e2e/rust/tests/additional_ca.rs`

No change was needed in `crates/openshell-server/src/compute/mod.rs` or
`compute/driver_config/builtin.rs`: Slice 1 already exposes the shared bundle
through the common build context, and the actual first-party Podman factory is
in `crates/openshell-gateway/src/lib.rs`.

### Automated verification

Passed the approved Slice 4 checks:

- `mise exec -- cargo test -p openshell-driver-podman` — 227 library tests and
  3 binary tests passed, including configured/unconfigured staging,
  rootful/rootless spec shapes, fixed read-only mount, dedicated argv,
  missing-artifact failure, proxy independence, driver-key rejection, and user
  override resistance.
- `mise exec -- cargo test -p openshell-server compute::driver_config` — 14
  focused tests passed.
- `mise exec -- cargo test -p openshell-server podman` — 1 matching server
  configuration test passed; all integration binaries completed with their
  unrelated tests filtered out.
- `mise exec -- cargo fmt --all -- --check` — passed.

Additional checks:

- `mise exec -- cargo check -p openshell-gateway` — passed, verifying the
  gateway factory-to-Podman constructor propagation path.
- `mise exec -- cargo clippy -p openshell-driver-podman --tests -- -D warnings`
  — passed.
- `git diff --check` — passed.
- Focused destination-trust and exact reserved-path tests passed after the
  final test refinement.
- `podman info --format '{{.Host.Security.Rootless}} {{.Host.NetworkBackend}}'`
  — reported `true netavark`.
- `mise exec -- cargo test --manifest-path e2e/rust/Cargo.toml --features e2e-podman --test additional_ca --no-run`
  — passed.
- `mise exec -- cargo test --manifest-path e2e/rust/Cargo.toml --features e2e-docker --test additional_ca --no-run`
  — passed, preserving the Slice 3 Docker target while sharing the local
  container test.
- `mise exec -- cargo clippy --manifest-path e2e/rust/Cargo.toml --features e2e-podman --test additional_ca -- -D warnings`
  — passed.
- `bash -n e2e/with-podman-gateway.sh e2e/rust/e2e-podman.sh` — passed.
- Final root-workspace and e2e-crate format checks plus `git diff --check` —
  passed.

### E2E verification status

No manual verification or human confirmation is required. At
2026-09-11T17:38:10Z the user explicitly waived all manual testing requirements
for this task and directed that the scenarios become CI e2e coverage. The
Podman e2e implementation and agent-run evidence are complete; wiring and
preserving all applicable driver lanes in CI remains a requirement for Slice 8.

Passed on the host's rootless Podman/netavark runtime:

- `OPENSHELL_CONFORMANCE_BIN=/mnt/build-artifacts/cargo-target/debug/openshell-conformance OPENSHELL_E2E_PODMAN_TEST=additional_ca mise exec -- e2e/rust/e2e-podman.sh`
  — the focused test passed (1 passed). It generated an ephemeral private CA
  and matching-host HTTPS fixture, configured the global gateway setting, and
  proved:
  - `host.openshell.internal` succeeded with the configured private CA;
  - the same endpoint via `host.containers.internal` failed hostname
    verification;
  - `https://example.com` remained trusted through the default/public roots;
  - supervisor readiness/output reached the gateway over the existing,
    separately mounted gateway mTLS CA;
  - live Podman inspection found exactly one destination-CA mount, read-only,
    distinct from `/etc/openshell/tls/client/ca.crt`; and
  - live argv contained exactly one
    `--network-additional-ca-bundle /etc/openshell-tls/network-additional-ca.crt`
    pair.
- `OPENSHELL_CONFORMANCE_BIN=/mnt/build-artifacts/cargo-target/debug/openshell-conformance OPENSHELL_E2E_PODMAN_TEST=podman_corporate_proxy mise exec -- e2e/rust/e2e-podman.sh`
  — the proxy-only suite passed (2 passed), including the HTTPS proxy CA-bundle
  case, with no global destination CA fixture enabled.

The first attempted live invocations exposed only harness issues: the direct
shell lacked Cargo on `PATH`, the conformance binary path needed the repository
`CARGO_TARGET_DIR`, and raw Podman inspection needed the wrapper's API socket
and network filter. The focused test was corrected to use the shared container
engine configuration and the final commands above pass. These failed harness
attempts are not treated as feature failures.

This live evidence is supplementary to the required CI e2e path. Slice 4 is
complete because its automated checks pass and the user explicitly removed the
manual gate; no human execution or confirmation of a manual checklist is
claimed.

### Deviations, risks, and follow-ups

- The actual Podman factory is in `crates/openshell-gateway/src/lib.rs`, not the
  outline's suggested server files. This matches the existing composition
  boundary and the Slice 3 Docker pattern.
- Rootful/rootless unit coverage exercises the same Podman spec builder with
  default and `userns = "auto"` shapes. The live e2e ran on rootless Podman;
  rootful behavior remains covered by the common spec test rather than a
  second live lane.
- Artifact existence validation and the Podman create operation are separate.
  If the file disappears after spec construction, Podman's required bind mount
  fails container creation rather than silently launching without the
  dedicated argument.
- No configuration field was added to `PodmanComputeConfig`; global material
  remains runtime launch state supplied only by the in-process gateway.
- The Slice 3 Docker-focused `additional_ca` e2e was generalized for both
  local-container drivers and expanded to cover public trust and callback
  evidence. The Podman wrapper owns only its opt-in ephemeral fixture and
  leaves normal Podman runs unchanged.
- No commit or push was made.

### Verification-policy update

On 2026-09-11 the user waived all remaining manual testing requirements for the
entire task and required the corresponding scenarios to be automated as e2e
tests that run in CI. The approved outline now treats the former Slice 4–8
manual sections as CI e2e/integration requirements. This waiver removes human
confirmation gates; it does not waive any scenario, permit unsupported lanes to
be omitted from CI, or allow a CI failure to be treated as passing.

## Slice 5 — Kubernetes ConfigMap and topology adapters

### Status

Complete on 2026-09-11. The Kubernetes adapter, topology placement tests, and
approved package/server/format checks pass. Focused combined and sidecar
Kubernetes e2e coverage is wired into the branch CI matrix. The live e2e was
not run locally because this checkout has no Docker, Helm, k3d, or kind runtime;
no local or CI live pass is claimed. Per the task-wide user waiver, there is no
manual verification gate, and CI failure remains blocking for final validation.

### Implemented behavior

- The in-process Kubernetes factory now clones the shared normalized
  `NetworkSupervisorTrustBundle` into `KubernetesComputeDriver`; the standalone
  external driver passes no bundle, consistent with the startup rejection for
  unsupported external delivery.
- Added stable gateway-scoped managed ConfigMap naming,
  `openshell-network-additional-ca-<gateway_id>`, the `ca.crt` key, and the
  reserved `openshell-network-additional-ca` pod volume. Invalid derived names
  fail startup before connecting to Kubernetes.
- Before creating a Sandbox CR, the driver server-side-applies one ConfigMap in
  the already-selected shared, managed, or operator target namespace. The
  object contains only normalized PEM plus OpenShell management and gateway
  identity labels. Repeated provisioning updates the same object; API errors
  and timeouts fail the sandbox operation without certificate content.
- Combined topology adds the read-only `ca.crt` subPath mount and dedicated
  argument only to the agent container running the combined supervisor.
  Sidecar topology adds them only to `openshell-network`. Process/agent,
  network-init, supervisor-sideload init, and workspace-init containers do not
  receive destination trust material.
- No bundle produces no managed ConfigMap API call, pod volume, mount, or
  argument. Gateway mTLS, service-account bootstrap, sidecar child trust-file
  handoff, corporate proxy, SPIFFE, and workspace volumes remain separate.
- The destination path and volume name are reserved against user Kubernetes
  driver-config overrides.
- The shared focused Rust e2e now supports Kubernetes. Its harness generates
  ephemeral CA/server material, mounts the operator source only into a
  restarted gateway, supplies test-only ConfigMap RBAC pending Slice 7, and
  inspects the managed ConfigMap and pod. It covers private trust, hostname
  mismatch, public trust, callback isolation, combined/sidecar placement, and
  unchanged running-supervisor trust after managed ConfigMap mutation.
- Added focused combined and sidecar Kubernetes CI matrix rows. A dedicated
  Cargo feature prevents the fixture-dependent test from running in ordinary
  no-fixture suites.

### Files changed

- `crates/openshell-driver-kubernetes/src/config.rs`
- `crates/openshell-driver-kubernetes/src/driver.rs`
- `crates/openshell-driver-kubernetes/src/main.rs`
- `crates/openshell-gateway/src/lib.rs`
- `e2e/rust/Cargo.toml`
- `e2e/rust/e2e-docker.sh`
- `e2e/rust/e2e-podman.sh`
- `e2e/rust/e2e-kubernetes.sh`
- `e2e/rust/tests/additional_ca.rs`
- `e2e/with-kube-gateway.sh`
- `.github/workflows/branch-e2e.yml`

### Automated verification

Passed the exact Slice 5 checks:

- `mise exec -- cargo test -p openshell-driver-kubernetes` — 240 library tests,
  2 binary tests, and doc tests passed.
- `mise exec -- cargo test -p openshell-server kubernetes` — 2 matching server
  tests passed; unrelated integration targets completed with tests filtered.
- `mise exec -- cargo fmt --all -- --check` — passed.

Additional checks passed:

- `mise exec -- cargo check -p openshell-gateway`.
- `mise exec -- cargo clippy -p openshell-driver-kubernetes --tests -- -D warnings`.
- `mise exec -- cargo clippy --manifest-path e2e/rust/Cargo.toml --features e2e-kubernetes,e2e-additional-ca --test additional_ca -- -D warnings`.
- `mise exec -- cargo test --manifest-path e2e/rust/Cargo.toml --features e2e-kubernetes,e2e-additional-ca --test additional_ca --no-run`.
- `mise exec -- cargo test --manifest-path e2e/rust/Cargo.toml --features e2e-docker,e2e-additional-ca --test additional_ca --no-run`.
- `mise exec -- cargo fmt --manifest-path e2e/rust/Cargo.toml -- --check`.
- `bash -n e2e/with-kube-gateway.sh e2e/rust/e2e-kubernetes.sh e2e/rust/e2e-docker.sh e2e/rust/e2e-podman.sh`.
- `git diff --check`.

Not run:

- The focused combined and sidecar Kubernetes live e2e rows. Local prerequisite
  probes found `kubectl` but no Docker CLI, Helm, k3d, or kind. The CI rows use
  `.github/workflows/e2e-kubernetes-test.yml` to provision kind.

### Manual verification status

Not required. The user waived all manual testing requirements on 2026-09-11
and required equivalent automated CI e2e coverage. This log does not claim a
human check or a live local/CI pass.

### Deviations, risks, and follow-ups

- The actual Kubernetes factory is in `crates/openshell-gateway/src/lib.rs`,
  not the outline's suggested server factory files.
- Slice 7 owns the production Helm source value/mount and least-privilege RBAC.
  To keep Slice 5's live driver e2e independently runnable, the Kubernetes e2e
  wrapper applies a test-only source mount, TOML stanza, and namespace
  Role/RoleBinding after chart install, then rolls the gateway. Slice 7 should
  replace this temporary adaptation with the production chart path.
- The managed ConfigMap uses a read-only `subPath` file mount. Trust is loaded
  at supervisor startup; running supervisors retain initialized trust until
  restart.
- Server-side apply fails on ownership conflicts instead of forcibly taking an
  existing object with the same gateway-derived name.
- No commit or push was made.

## Slice 6 — VM overlay and guest-init adapter

### Status

Complete on 2026-09-11. The VM gateway-to-driver contract, per-sandbox overlay
staging/removal, guest-init argument delivery, package tests, and CI e2e wiring
are implemented. The focused live VM e2e was not run locally because `/dev/kvm`
is unavailable and no built VM driver/runtime bundle is present. The CI VM lane
now includes a dedicated `additional-ca` row. Per the task-wide user waiver,
there is no manual verification gate; no local or CI live pass is claimed.

### Implemented behavior

- The first-party VM factory passes only the gateway-owned normalized artifact
  path to the managed `openshell-driver-vm` subprocess through the hidden
  `--network-additional-ca-bundle` option. The option has no environment alias
  and is not part of `[openshell.drivers.vm]` deserialization.
- `VmDriverConfig` keeps the optional artifact as internal launch state, redacts
  its path from `Debug`, and validates empty-path misuse. Gateway mTLS inputs,
  proxy CA inputs, and guest environment construction remain separate.
- Every fresh or preserved-overlay sandbox launch re-reads the gateway artifact
  through the bounded regular-file/usable-certificate validator before launch.
  Missing, non-regular, oversized, or unusable material fails provisioning
  without logging certificate contents.
- Configured normalized bytes are written into the overlay upper layer at
  `/etc/openshell-tls/network-additional-ca.crt` with mode `0444`. Replacement
  rewrites the reserved file before launch. A restart with no configured bundle
  removes the old upper-layer file, so old destination trust is not retained.
- The existing driver-authored `/opt/openshell/supervisor-args` marker carries
  exactly `--network-additional-ca-bundle` and the fixed guest path when the
  artifact is configured. It is rewritten empty when configuration is absent,
  preventing a guest image or ordinary guest environment from activating the
  argument.
- Both libkrun and QEMU already execute the same embedded guest-init path and
  attach the same writable overlay. Tests pin that shared path and the
  driver-owned argument-file consumption; no backend-specific environment or
  callback trust changes were introduced.
- Added an idempotent, path-validated ext4 image removal helper and test-only
  debugfs read/stat helpers used to verify real overlay bytes, permissions,
  replacement, and clearing.
- Extended the shared `additional_ca` e2e test and VM wrapper. The wrapper
  generates an ephemeral matching-host private-CA HTTPS fixture, renders the
  global configuration, and the test covers private trust, hostname mismatch,
  public trust, callback activity, overlay digest/argv inspection, and serial
  log redaction. Branch CI now runs the normal VM suite and a dedicated
  `additional-ca` VM suite.

### Files changed

- `crates/openshell-gateway/src/lib.rs`
- `crates/openshell-gateway/src/vm.rs`
- `crates/openshell-driver-vm/Cargo.toml`
- `crates/openshell-driver-vm/src/main.rs`
- `crates/openshell-driver-vm/src/driver.rs`
- `crates/openshell-driver-vm/src/rootfs.rs`
- `e2e/rust/e2e-vm.sh`
- `e2e/rust/tests/additional_ca.rs`
- `.github/workflows/e2e-vm-test.yml`
- `.github/workflows/branch-e2e.yml`

`crates/openshell-driver-vm/src/runtime.rs` and the guest-init script required
no behavior change: both supported runtime backends already use the common
per-sandbox overlay and common embedded init script, while the existing
supervisor-args marker already provides the required driver-owned activation
boundary.

### Automated verification

Passed the exact applicable Slice 6 checks:

- `mise exec -- cargo test -p openshell-driver-vm` — 197 library tests, 18
  binary tests, and doc tests passed. New coverage includes configured bytes,
  `0444` mode, replacement and removal on a preserved overlay, missing artifact
  failure/redaction, fixed guest argv, hidden CLI parsing, and common
  libkrun/QEMU guest-init delivery.
- `mise exec -- cargo test -p openshell-server compute::vm` — command passed,
  but the stale outline filter matched zero tests because VM process composition
  lives in `openshell-gateway`, not `openshell-server`.
- `mise exec -- cargo test -p openshell-gateway vm` — 25 VM composition tests
  passed, including configured/unconfigured internal option propagation and
  separation from `OPENSHELL_TLS_CA`.
- `mise exec -- cargo fmt --all -- --check` — passed.

Additional checks passed:

- `mise exec -- cargo clippy -p openshell-driver-vm --tests -- -D warnings`.
- `mise exec -- cargo test --manifest-path e2e/rust/Cargo.toml --features e2e-vm,e2e-additional-ca --test additional_ca --no-run`.
- `mise exec -- cargo clippy --manifest-path e2e/rust/Cargo.toml --features e2e-vm,e2e-additional-ca --test additional_ca -- -D warnings`.
- `mise exec -- cargo fmt --manifest-path e2e/rust/Cargo.toml -- --check`.
- `bash -n e2e/rust/e2e-vm.sh`.
- `git diff --check`.

A broader combined gateway/VM Clippy diagnostic reached pre-existing Slice 1
`clippy::redundant_pub_crate` findings in the private
`openshell-server::network_trust` module. The focused VM-driver Clippy check
passes; this slice did not alter those unrelated visibility declarations.

### E2E verification status

No manual verification is required. The user waived all manual testing on
2026-09-11 and required equivalent automated CI e2e coverage. The VM wrapper
and reusable workflow compile and are wired to run the focused test as
`E2E (rust-vm-additional-ca)`.

Not run locally:

- `OPENSHELL_E2E_VM_TEST=additional_ca e2e/rust/e2e-vm.sh` — local probes found
  `qemu-system-x86_64`, `debugfs`, and `openssl`, but `/dev/kvm` is unavailable,
  `target/debug/openshell-driver-vm` is absent, and no prepared compressed VM
  runtime files are present. The live command is therefore deferred to the
  required CI VM runner. No local or CI pass is claimed, and a CI failure
  remains blocking for final validation.

### Deviations, risks, and follow-ups

- The outline cited `crates/openshell-server/src/compute/vm.rs`, but current VM
  process composition is in `crates/openshell-gateway/src/vm.rs` and the
  first-party factory is in `crates/openshell-gateway/src/lib.rs`. The
  implementation follows the current authoritative boundary.
- The shared ext4 write helper replaces files while the guest is stopped. There
  is no guest-visible partial state: any read, write, chmod, removal, or
  argument-marker failure aborts provisioning before either runtime backend is
  launched.
- The live focused VM row covers initial trust and delivery inspection. The
  preserved-overlay replacement/removal lifecycle is covered by a real ext4
  unit test; Slice 8 still owns the complete cross-driver live restart/removal
  matrix and final hardening.
- The `additional_ca` e2e source fixture compares only SHA-256 digests when
  inspecting VM overlay material and refuses PEM output in the serial log.
- No commit or push was made.

## Slice 7 — Helm delivery and documentation

### Status

Complete on 2026-09-11. The chart now delivers an operator-owned source
ConfigMap through the global supervisor-network setting and grants the
Kubernetes driver ConfigMap apply permissions only when the feature is enabled.
Helm lint, default/configured renders, all chart unit tests, workspace format,
Helm documentation generation checks, and Fern documentation validation pass.
The existing focused Kubernetes CI lanes now exercise the production chart
upgrade and restart lifecycle instead of patching the gateway workload and RBAC
out of band. No manual verification gate remains under the task-wide waiver.

### Implemented behavior

- Added `supervisor.network.additionalCaConfigMapName`, defaulting empty. When
  set, the chart expects an operator-owned ConfigMap in the gateway namespace
  with a `ca.crt` key.
- The chart mounts that key read-only at
  `/etc/openshell-tls/network-additional-ca-source/ca.crt` in the gateway and
  renders
  `[openshell.supervisor.network].additional_ca_cert_paths` at the global TOML
  location. The source path is distinct from the sandbox destination path.
- Default values render no global table, source mount, volume, or destination
  ConfigMap permission. A missing legacy `supervisor.network` map is also
  treated as disabled.
- Shared mode grants `get`, `create`, and `patch` on ConfigMaps through the
  sandbox namespace Role only when additional trust is enabled. The Role and
  binding still render with only that rule when `workspaceResources.enabled`
  is false. Managed and operator modes add the same gated rule to the existing
  ClusterRole.
- The focused Kubernetes additional-CA wrapper now creates the source ConfigMap
  before chart installation, enables the feature with a real `helm upgrade`,
  verifies the gateway config checksum changes, inspects the chart-owned source
  volume, and confirms the gateway ServiceAccount can apply ConfigMaps. It then
  changes only the source ConfigMap, proves that no workload checksum or pod UID
  changes, and explicitly restarts the gateway before sandbox trust assertions.
  The prior test-only TOML, workload, and RBAC patches were removed.
- Updated the Helm README source template and regenerated README with a
  ConfigMap example, trust scope, RBAC note, and restart lifecycle.
- Updated the published gateway configuration reference with PEM/path rules,
  strict failures, additive trust, driver delivery, unsupported remote/custom
  behavior, fixed path/argument, lifecycle, Helm mapping, and separation from
  proxy, callback, listener, OIDC, middleware, and interceptor trust.
- Updated the sandbox architecture, RFC 0003 schema, and Docker, Kubernetes,
  Podman, and VM driver documentation with the stable shared contract and
  driver-specific staging boundaries.

### Files changed

- `deploy/helm/openshell/values.yaml`
- `deploy/helm/openshell/templates/gateway-config.yaml`
- `deploy/helm/openshell/templates/_gateway-workload.tpl`
- `deploy/helm/openshell/templates/role.yaml`
- `deploy/helm/openshell/templates/rolebinding.yaml`
- `deploy/helm/openshell/templates/clusterrole.yaml`
- `deploy/helm/openshell/tests/network_additional_ca_test.yaml` (new)
- `deploy/helm/openshell/README.md.gotmpl`
- `deploy/helm/openshell/README.md` (regenerated)
- `docs/reference/gateway-config.mdx`
- `architecture/sandbox.md`
- `rfc/0003-gateway-configuration/README.md`
- `crates/openshell-driver-docker/README.md`
- `crates/openshell-driver-kubernetes/README.md`
- `crates/openshell-driver-podman/README.md`
- `crates/openshell-driver-vm/README.md`
- `e2e/with-kube-gateway.sh`

### Automated verification

Passed the exact Slice 7 checks:

- `mise exec -- helm lint deploy/helm/openshell --set agentSandbox.preflight.enabled=false`
  — chart lint passed; only the existing icon recommendation was reported.
- `mise exec -- helm template openshell deploy/helm/openshell --set agentSandbox.preflight.enabled=false`
  — default render produced valid non-empty YAML with no additional-CA table,
  mount, or permission.
- `mise exec -- helm unittest deploy/helm/openshell` — 13 suites and 154 tests
  passed, including global TOML placement, source mount/key, default omission,
  null-map compatibility, checksum presence, and shared/managed/operator RBAC.
- `mise exec -- cargo fmt --all -- --check` — passed.

Additional checks passed:

- Configured `helm template` renders for shared, managed, and operator workspace
  modes, with exact global source path and ConfigMap permissions.
- `mise run helm:docs:check` — generated Helm README is current.
- `mise run docs` — Fern reported 0 errors and 3 existing warnings.
- Documentation contract-marker checks found the exact global table, field,
  fixed guest path, and supervisor argument across the reference,
  architecture, RFC, Helm, and driver documentation.
- `bash -n e2e/with-kube-gateway.sh` — passed.
- `git diff --check` — passed.

The first Helm unit-test run failed because the new suite incorrectly placed
`template` selectors on individual assertions; helm-unittest applied those
assertions to every template. The suite was split into template-scoped tests.
The final complete run above passes; this was a test-definition issue, not a
chart behavior failure.

Not run:

- The live combined and sidecar Kubernetes additional-CA CI rows. This checkout
  still lacks Docker, k3d, and kind, so no local cluster is available. The
  wrapper syntax and chart contracts pass locally, and the already-wired branch
  CI rows now execute the production Helm upgrade/source-restart path. No local
  or CI live pass is claimed.
- `shellcheck e2e/with-kube-gateway.sh` because `shellcheck` is not installed;
  `bash -n` passes.

### Manual verification status

Not required. The user waived all manual testing requirements on 2026-09-11 and
required equivalent automated CI coverage. This log does not claim a human
check or a live local/CI pass.

### Deviations, risks, and follow-ups

- The outline left the Helm value's exact spelling open. The implementation uses
  `supervisor.network.additionalCaConfigMapName` and keeps the source key fixed
  at `ca.crt`.
- Shared mode creates a narrowly scoped Role and RoleBinding for ConfigMap apply
  even when `workspaceResources.enabled=false`; it does not re-enable sandbox
  CR, Event, or Pod permissions owned by the separate workspace chart.
- Kubernetes RBAC cannot restrict `create` by ConfigMap name. The grant is gated
  on the feature and namespace-scoped in shared mode; managed/operator modes
  already require cluster-wide access to selected workspace namespaces.
- Updating the operator-owned source ConfigMap cannot participate in the chart's
  rendered-config checksum. The CI wrapper explicitly verifies that it does not
  roll the gateway and then performs the documented restart.
- No commit or push was made.

## Slice 8 — Cross-driver regression, e2e, and final hardening

### Status

Active after partial implementation and focused verification. The shared live
test passes on the locally available rootless Podman lane. Repository-wide
checks previously stopped because the shared Cargo target filesystem reached
100% usage; on 2026-09-11 the user authorized deletion of the 60 GB incremental
build cache, restoring 60 GB free space, so the task was reactivated. Docker,
Kubernetes, and VM live lanes remain CI-only here. The Slice 8 checkbox remains
open and state continues to point at Slice 8.

### Implemented behavior and coverage

- Consolidated four duplicated private-CA/HTTPS implementations into
  `e2e_start_additional_ca_fixture` in `e2e/support/gateway-common.sh`. All four
  driver wrappers now use the same generated CA, leaf SAN, HTTPS server,
  readiness check, and redacted environment contract.
- Made hostname rejection structural: curl uses `--connect-to` to reach the
  known-good `host.openshell.internal` fixture while retaining
  `mismatch.openshell.internal` as the URL/SNI name, and requires curl status
  60. DNS or routing failure can no longer satisfy the assertion.
- Extended the live flow to replace each driver boundary's staged material with
  invalid content and require a new sandbox to fail provisioning without PEM or
  private-key disclosure. Local container and VM lanes mutate the gateway-owned
  artifact; Kubernetes mutates the driver-managed ConfigMap. The already-running
  Kubernetes supervisor also retains its startup-loaded trust.
- Removed the synthetic callback-success echo. Workload execution and relay exec
  are the positive callback evidence; the shared two-CA `grpc_client` test
  remains the negative destination/gateway trust-isolation proof.
- Added configured additional-CA jobs to the default Docker and Podman reusable
  CI matrices. Existing Slice 5/6 changes already schedule Kubernetes combined,
  Kubernetes sidecar, and VM configured lanes.
- Exported the gateway-owned staged artifact path only to the configured local
  and VM test harnesses. It is not exposed to sandbox environment or product
  configuration.
- Narrowed the new server module's item visibility for repository Clippy.

### Files changed in this slice

- `.github/workflows/e2e-docker-test.yml`
- `.github/workflows/e2e-podman-test.yml`
- `crates/openshell-server/src/network_trust.rs`
- `e2e/support/gateway-common.sh`
- `e2e/with-docker-gateway.sh`
- `e2e/with-podman-gateway.sh`
- `e2e/with-kube-gateway.sh`
- `e2e/rust/e2e-vm.sh`
- `e2e/rust/tests/additional_ca.rs`

### Automated verification

Passed:

- Shared fixture smoke: `openssl verify`, SAN inspection, and an HTTPS curl with
  the generated CA.
- `bash -n` over the shared helper, four wrappers, and four Rust e2e launch
  scripts.
- Compile-only additional-CA test targets for Docker, Podman, Kubernetes, and
  VM.
- Combined-driver Clippy for `e2e/rust/tests/additional_ca.rs` with warnings
  denied.
- Rootless Podman live command:
  `OPENSHELL_CONFORMANCE_BIN=/mnt/build-artifacts/cargo-target/debug/openshell-conformance
  OPENSHELL_E2E_PODMAN_TEST=additional_ca mise exec --
  e2e/rust/e2e-podman.sh` — conformance and the focused test passed, including
  private trust, structural hostname rejection, public trust, callback/relay
  activity, mount/argv inspection, and invalid staged-material failure for a
  new sandbox.
- Workflow YAML parsing and Docker/Podman JSON matrix validation.
- `mise exec -- cargo test -p openshell-server network_trust` — 15 tests passed
  after visibility hardening.
- Workspace/e2e format checks and `git diff --check` passed before disk
  exhaustion.

Blocked or not run:

- `mise run pre-commit` reached workspace Clippy and failed on three pre-existing
  Landlock warnings in
  `crates/openshell-supervisor-process/src/sandbox/linux/landlock.rs`. It also
  found two new redundant-visibility warnings; those were fixed. The complete
  command was not rerun after the target filesystem filled.
- `mise run test` progressed through non-Rust suites and most workspace Rust
  tests, then failed while building the final `openshell-server --features
  test-support` phase with `No space left on device` and an LLD bus error.
  `/mnt/build-artifacts` had 259 MiB available and reported 100% usage. This is
  an infrastructure failure, not a test assertion failure, but the command is
  not claimed passing.
- `mise run e2e` was not run: the host has no Docker CLI/daemon or local
  Kubernetes runtime, no usable VM/KVM bundle, and the Cargo target volume is
  full. Only the Podman lane above is claimed passing.
- Docker, Kubernetes combined/sidecar, and VM configured lanes are wired for CI,
  but no CI result is claimed.

### Deviations, risks, and follow-ups

- The approved live matrix's explicit “remove config + restart” scenario is not
  yet one end-to-end flow for every driver. Existing no-setting CI lanes and
  driver contract tests cover omission/removal boundaries, and VM has real
  overlay replacement/removal coverage, but this does not satisfy the stricter
  Slice 8 live lifecycle wording. Complete or explicitly reapprove that coverage
  allocation before marking Slice 8 complete.
- Invalid source material and unsupported remote/custom drivers remain covered
  by Slice 1's real-gateway process test rather than duplicated in every driver
  lane. Invalid staged material now has driver-backed coverage.
- The callback positive path runs through successful readiness and relay exec in
  each configured lane. Negative isolation remains the shared two-CA TLS/H2
  test; no fake gateway is launched separately per compute-driver lane.
- Free space on `/mnt/build-artifacts`, then rerun `mise run pre-commit`,
  `mise run test`, and applicable e2e/CI lanes. Do not mark the slice complete
  until checks pass and the lifecycle coverage gap is resolved.
- No manual verification is required under the task-wide waiver. No commit or
  push was made.

### Slice 8 continuation — removal/restart lifecycle (2026-09-11)

Implemented the remaining live lifecycle scenario in the shared driver-backed
`additional_ca` test:

- Docker, Podman, and VM wrappers now export the wrapper-owned gateway TOML path.
  After configured trust and invalid-staged-material checks, the test removes
  the complete `[openshell.supervisor.network]` section, restarts the managed
  gateway, and waits for health.
- Kubernetes exports its Helm release, namespace, and chart identity. The test
  removes `supervisor.network.additionalCaConfigMapName` with a production chart
  upgrade and waits for the rolled gateway to become healthy.
- A new sandbox after restart asserts the reserved destination bundle file is
  absent and the same previously reachable private-CA HTTPS fixture is no longer
  trusted. The assertion accepts the driver-appropriate TLS failure shape: a
  direct curl may report unknown issuer, while an intercepting supervisor may
  reset the request after its upstream TLS verification rejects the issuer.
- The existing configured-trust success in the same process makes the removal
  rejection non-vacuous; DNS, policy, fixture reachability, and hostname were
  already proven before the restart.
- Changed the private gateway `network_trust` module's parent-facing items from
  `pub(super)` to `pub` to satisfy the repository's
  `clippy::redundant_pub_crate` policy. The private module still prevents these
  items from becoming an external API.

Files changed in this continuation:

- `e2e/rust/tests/additional_ca.rs`
- `e2e/with-docker-gateway.sh`
- `e2e/with-podman-gateway.sh`
- `e2e/with-kube-gateway.sh`
- `e2e/rust/e2e-vm.sh`
- `crates/openshell-server/src/network_trust.rs`

Verification results:

- Four compile-only focused targets passed for Docker, Podman, Kubernetes, and
  VM with `e2e-additional-ca` enabled.
- Combined-driver Clippy for `additional_ca.rs` passed with warnings denied.
- `bash -n` over the shared helper, four wrappers, and four Rust e2e launch
  scripts passed.
- `mise exec -- cargo test -p openshell-server network_trust` passed: 15 tests.
- `mise run test` passed after free space was restored, including 1,532
  `openshell-server` library tests (8 ignored) and all workspace integration and
  non-Rust suites.
- `mise exec -- cargo fmt --all -- --check` and `git diff --check` passed.
- The first updated Podman live run reached the no-setting sandbox but expected
  curl status 60; the supervisor correctly rejected upstream TLS and surfaced a
  connection reset (status 56) through its interception path. The assertion was
  corrected to require any nonzero result against the same already-proven live
  fixture, while also requiring the reserved CA file to be absent.
- The final rootless Podman live command passed end to end:
  `OPENSHELL_CONFORMANCE_BIN=/mnt/build-artifacts/cargo-target/debug/openshell-conformance
  OPENSHELL_E2E_PODMAN_TEST=additional_ca mise exec --
  e2e/rust/e2e-podman.sh`. It now includes configured private/public trust,
  structural hostname rejection, callback/relay activity, mount/argv
  inspection, invalid staged material, gateway config removal/restart, omitted
  reserved path, and rejection of the formerly trusted private CA.

Blocked verification:

- `mise run pre-commit` still fails workspace Clippy on three unrelated Landlock
  warnings in
  `crates/openshell-supervisor-process/src/sandbox/linux/landlock.rs`: missing
  backticks around `prompt_toolkit`, a redundant closure, and an
  `Option::map_or_else` preference. The two network-trust visibility findings
  from the same run were fixed and pass focused Clippy. The Landlock behavior is
  outside this task; it requires explicit approval for an unrelated cleanup or
  a baseline/toolchain resolution before Slice 8 can complete.
- Docker is unavailable locally; Kubernetes lacks Docker/kind/k3d; and VM lacks
  `/dev/kvm` and prepared runtime artifacts. Their configured lifecycle lanes
  compile and are wired into CI, but no live result is claimed. `mise run e2e`
  remains inapplicable on this host for those lanes.

Slice 8 remains open because the required pre-commit command has not passed and
CI-only Docker, Kubernetes combined/sidecar, and VM live results have not been
observed. No manual verification is required, and no commit or push was made.

### Slice 8 continuation — Clippy blocker cleared (2026-09-11)

The user explicitly approved fixing the unrelated Landlock Clippy baseline.
The cleanup in
`crates/openshell-supervisor-process/src/sandbox/linux/landlock.rs`:

- formats `prompt_toolkit` as code in rustdoc;
- replaces a redundant closure with `Ruleset::create`; and
- expresses the fallback result with `map_or_else` without changing success or
  unreachable failure behavior.

The full workspace lint then exposed two task-owned test-only findings that had
been hidden behind the earlier failures. These were also corrected: an
unnecessary raw-string hash in `config_file.rs` and a cloned one-element path
slice in `network_trust.rs`.

Verification passed:

- `mise exec -- cargo test -p openshell-supervisor-process
  sandbox::linux::landlock` — 20 focused tests passed.
- `mise exec -- cargo clippy -p openshell-supervisor-process --all-targets -- -D
  warnings` — passed.
- `mise run pre-commit` — passed in full, including workspace/all-target Clippy,
  formatting, lockfile, license, Python, Helm, Markdown, protobuf, TypeScript,
  e2e Rust, and example checks.
- `git diff --check` — passed.

The local Clippy/pre-commit block is cleared. Slice 8 remains active only for
observing the configured Docker, Kubernetes combined/sidecar, and VM CI e2e
results required by the approved matrix. No commit or push was made.

### Slice 8 continuation — CI publication blocker (2026-09-11)

The remaining approved Slice 8 action was to obtain configured Docker,
Kubernetes combined/sidecar, and VM CI e2e results. Repository and GitHub state
were inspected without committing or pushing, as required by the task request:

- The local branch is `feat/network-supervisor-additional-ca` at `86b30e8b` and
  has no configured upstream.
- `git ls-remote --heads origin feat/network-supervisor-additional-ca` returned
  no remote branch.
- `gh run list --branch feat/network-supervisor-additional-ca` returned no
  workflow runs.
- `gh pr list --head feat/network-supervisor-additional-ca --state all`
  returned no pull request.
- All feature and CI workflow changes remain uncommitted in this worktree, so a
  GitHub Actions dispatch against the current implementation is impossible:
  GitHub has no commit/ref containing the code or the configured matrix rows.

No automated check was rerun in this continuation because the required local
checks already pass in the immediately preceding log entries and the only
remaining checks require the unpublished GitHub ref. No source or test code was
changed.

Slice 8 is blocked, not complete. Its checkbox remains open and no Docker,
Kubernetes combined/sidecar, or VM CI pass is claimed. The next action requires
explicit user authorization to commit the verified work with DCO signoff and
push the branch (or another user-provided remote ref containing these exact
changes), after which the configured CI lanes can be dispatched/observed. No
commit or push was made.

### Slice 8 continuation — commit authorization (2026-09-11)

The user explicitly authorized committing the complete verified work. Before
staging, `mise run pre-commit` passed in full again, including workspace and e2e
Rust formatting/Clippy, lockfiles, license headers, Python, Helm, Markdown,
protobuf, TypeScript, and example checks. `git diff --check` also passed.

The commit is authorized with Conventional Commit format, DCO signoff, and the
repository's configured GPG signing. Push remains unauthorized. After the
commit, Slice 8 will remain blocked until the user authorizes publishing the
branch so the configured Docker, Kubernetes combined/sidecar, and VM CI lanes
can run. No CI pass is claimed.
