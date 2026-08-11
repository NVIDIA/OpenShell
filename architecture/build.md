# Build

This page records the stable build, CI, docs, and release architecture. It is
not a command reference. Contributor-facing workflow details live in
`CONTRIBUTING.md`, `CI.md`, and published docs.

## Artifacts

OpenShell builds these main artifacts:

| Artifact | Source |
|---|---|
| Gateway binary | `crates/openshell-server` |
| CLI package and Python SDK | `python/openshell` plus Rust binaries where packaged |
| Gateway container image | `deploy/docker/Dockerfile.gateway` |
| Supervisor container image | `deploy/docker/Dockerfile.supervisor` |
| Helm chart | `deploy/helm/openshell` |
| VM driver/runtime assets | `crates/openshell-driver-vm` |
| Published docs site | `docs/` rendered by Fern config in `fern/` |

Sandbox community images are built outside this repository.

## Build Features

Anonymous telemetry emission is gated behind a default-on `telemetry` Cargo
feature. It is defined in `openshell-core` (where the emission code, HTTP
client, and endpoint live) and forwarded by the binary crates that emit or
collect telemetry: `openshell-server` (gateway), `openshell-sandbox`
(supervisor), and `openshell-driver-vm`. Every crate depends on
`openshell-core` with `default-features = false`, so the binary crate's feature
is the single switch that enables `openshell-core/telemetry` for its build
graph. In-process drivers (`docker`, `kubernetes`, `podman`) inherit the
gateway's setting through feature unification and carry no passthrough.

Building a binary with `--no-default-features` compiles out telemetry entirely:
no endpoint, no telemetry HTTP client, and no emission code. With telemetry
compiled out, `telemetry::enabled()` is always `false` and the `emit_*` helpers
are no-ops, so the data-model types stay available and dependent crates compile
unchanged. The runtime `OPENSHELL_TELEMETRY_ENABLED` switch remains the way to
disable telemetry in a default (telemetry-enabled) build.

Supervisor upstream TLS root-store selection is controlled by the
`bundled-ca-roots` Cargo feature (on by default). Default builds use Mozilla
roots through `webpki-roots` plus locally-installed CAs from the system bundle.
Building without `bundled-ca-roots` switches to the platform trust store via
`rustls-native-certs` and excludes bundled Mozilla root crates such as
`webpki-roots` and `webpki-root-certs` from the dependency graph. The
`system-ca-roots` feature alias on `openshell-sandbox` includes all other
defaults (currently `telemetry`) except `bundled-ca-roots`, so Linux
distribution builds (e.g. RPM) can use
`--no-default-features --features system-ca-roots` without manually re-adding
unrelated defaults. Other Rustls clients use native roots directly because that
already satisfies Linux distribution trust-store policy.

The workspace uses `z3` versions whose `z3-sys` dependency keeps downloader
HTTP/TLS support behind explicit build features, so default system-Z3 builds do
not reintroduce bundled Mozilla roots. Release builds that need bundled Z3
continue to opt in with `bundled-z3`.

## Crypto Backend Selection

`openshell-crypto` is the single point of cryptographic backend selection. Every
TLS, PKI, JWT, AEAD, and RNG operation routes through it, along with hashing that
serves a cryptographic purpose, so the backend is one feature rather than an
audit of call sites. Content and revision hashing is out of scope — see below. No other
crate may name a backend directly, and the workspace `rustls`, `tokio-rustls`,
and `rcgen` entries deliberately declare no backend feature — adding one back
would link `ring` unconditionally and silently defeat the FIPS build.

`fips` is a one-way switch rather than one half of a mutually exclusive pair.
`ring` is an unconditional dependency of `openshell-crypto`; enabling `fips`
additionally compiles in AWS-LC and moves every selection to it. There is no
`backend-ring` feature, deliberately: Cargo features are additive, so two
mutually exclusive backend features can always both be enabled at once, and any
dependency that resolves that ambiguity toward `ring` would yield a build that
reports FIPS while using unvalidated crypto.

Where a dependency selects for itself and the ambiguity cannot be removed, it is
rejected at compile time. `openshell-server` carries a `compile_error!` for
`fips` + `db-tls-ring` because sqlx prefers `ring` when both of its backends are
enabled. This is why a FIPS gateway is built with
`--no-default-features --features fips,telemetry` and has to re-list its
non-crypto defaults.

FIPS mode is selected at build time, not at runtime. On rustls 0.23 the
`require_ems` mechanism forces that; from 0.24 it becomes a deliberate choice
rather than a constraint, because `ring` is already linked in a FIPS build and one
artifact could dispatch between backends at runtime.

We keep build-time selection because it makes *which module is in use* a property
of the artifact rather than of a code path. A runtime switch would make the
guarantee depend on every dispatch site being correct and would leave a
non-validated path reachable in a FIPS deployment. See the 0.24 migration note
below.

### Three enforcement mechanisms, three surfaces

No single check covers the whole build. Each dependency class that selects its own
provider needs its own enforcement, and it is worth knowing which one covers what:

| Mechanism | Covers | When it fires |
|---|---|---|
| `verify_fips_posture()` | Everything that uses the process-default provider: OpenShell's own TLS, `reqwest`, `kube`, `tokio-tungstenite` | Gateway and CLI startup |
| `compile_error!` on `fips` + `db-tls-ring` | Database TLS, which `sqlx` selects from its own features | Compile time |
| `aws_crypto_mode()` and its unit test | The AWS SDK path, which `aws-smithy-http-client` selects for itself | Test time; smithy's own internal assertion fires on first connector request |

The boundary matters: `verify_fips_posture()` reads
`CryptoProvider::get_default()`, so it cannot see `sqlx`'s or smithy's provider at
all. A build that wired the AWS path to `ring` would still pass the startup check —
only the mode test catches that. Treating the startup check as a whole-process
guarantee is the mistake this table exists to prevent.

On rustls 0.23 `require_ems` (the TLS 1.2 extended-master-secret requirement) is
also derived from `cfg!(feature = "fips")`, which makes that behavior
compile-time too. That is a version-specific mechanism, not the underlying
reason — see the 0.24 migration note below.

Algorithm restriction comes from `rustls::crypto::default_fips_provider()`
rather than a hand-maintained suite list, so the approved set tracks rustls's
view of the module's validated boundary. `install_default_provider()` installs it
as the process default, which every `ClientConfig::builder()` and
`ServerConfig::builder()` call then inherits without threading a provider
through call sites. `verify_fips_posture()` runs at gateway and CLI startup and
fails the process if the *installed* provider is not FIPS-approved. It reads
`CryptoProvider::get_default()` rather than a freshly built provider, so it
catches both a mis-plumbed feature and a provider installed by something that
won the race. `ensure_default_provider()` covers library code that builds TLS
clients without a binary entry point having run first; it only fills in a
missing provider and never replaces one.

Two dependencies do not honor the process default and are handled separately.
`sqlx` selects a provider from its own features, so `openshell-server` forwards
the backend choice to it, at the cost of losing native-root loading in FIPS mode.
`aws-smithy-http-client` constructs its own provider, so the gateway builds the
AWS SDK's HTTPS client explicitly (`provider_refresh::aws_http_client`) with a
`CryptoMode` chosen by the `fips` feature; that also let the SDK's legacy
`rustls 0.21` TLS features be dropped, leaving one rustls major in the graph.
`mise run fips:audit` reports the residual surface.

`aws-sigv4` cannot be handled either way: it depends on RustCrypto `hmac` and
`sha2` unconditionally with no backend feature. SigV4 request signing therefore
computes HMAC-SHA256 outside the validated module in every build mode, on two
paths — proxy-side signing in `openshell-supervisor-network`, and the gateway's
STS `AssumeRole` requests, which `aws-sdk-sts` signs via `aws-runtime`. Moving the
STS *transport* to the validated module (Phase 2) did not change its *signing*.

Hashing is routed through the facade where it is a security function — key
identifiers, credential-storage key identifiers, and Kubernetes Secret and Vault
credential path derivation. Content and revision hashing (policy revisions,
profile catalogs, image digests) stays on RustCrypto `sha2`; those are
content-addressing rather than cryptographic use.

Build-mode differences that are visible outside the process — the JWT signing
algorithm, the SSH host key type, and the database trust store — are documented
in `docs/security/fips.mdx`.

### rustls 0.24 migration note

The FIPS feature plumbing described above is written against rustls 0.23 and will
not carry forward unchanged. rustls is removing the `fips` feature from the core
crate on `main` (targeting 0.24) and moving the behaviors it controlled — notably
`require_ems` — to key off the provider's declared FIPS status at runtime. The
feature is retained on a separate `rustls-aws-lc-rs` provider crate, where it both
activates `aws-lc-rs/fips` and statically determines the provider's make-up. See
[rustls/rustls#3054](https://github.com/rustls/rustls/issues/3054).

Neither is released yet: rustls 0.24 exists only as a `0.24.0-dev` prerelease and
`rustls-aws-lc-rs` is not published. rustls maintainers have stated 0.23 will not
change, so nothing here is affected today.

What the upgrade will require:

- `openshell-crypto`'s `fips` feature lists `rustls/aws_lc_rs` and `rustls/fips`.
  Both cease to exist; the equivalent moves to `rustls-aws-lc-rs/fips`.
- `provider()` calls `rustls::crypto::default_fips_provider()`, which is gated on
  the core `fips` feature today and will move with it.
- `verify_fips_posture()` becomes *more* load-bearing, not less. Once rustls
  derives its behavioral adaptations from `provider.fips()` at runtime, that
  return value governs actual protocol behavior rather than only reporting
  posture, so an unnoticed non-FIPS provider would silently relax TLS 1.2
  handling instead of merely mislabeling the build.

What the upgrade will **not** change: OpenShell will still ship separate FIPS and
non-FIPS artifacts. That is a product decision, not a hard limit — a single
artifact could link the FIPS provider and select policy at runtime, and `ring` is
already present for a non-FIPS path. We decline because runtime dispatch turns the
FIPS guarantee into a per-call-site property instead of an artifact-level one,
which is precisely what the design set out to avoid. rustls maintainers also
advise against running a FIPS provider in non-FIPS mode, given its slower update
cadence and performance-costing countermeasures.

## Linux Runtime Environments

OpenShell uses different Linux libc environments for different host artifacts.
The standalone `openshell` CLI is built as a static musl binary so it can run on
a wide range of Linux distributions without depending on the host's glibc. Host
runtime binaries that use the GNU/Linux runtime environment are GNU-linked.
`openshell-gateway` and `openshell-driver-vm` are built with a glibc 2.28 floor.
The gateway bundles z3 into the release binary so Linux packages, standalone
tarballs, and gateway images do not depend on distro-specific z3 shared-library
SONAMEs.

## Container Builds

The Docker image pipeline is a two-step flow: build the Rust binary natively
for the target architecture, then assemble the container image from the
prebuilt binary. The gateway image is built from `deploy/docker/Dockerfile.gateway`
and the supervisor image from `deploy/docker/Dockerfile.supervisor`. Neither
Dockerfile compiles Rust — both copy a staged binary out of
`deploy/docker/.build/prebuilt-binaries/<arch>/` into the final image.

Binary staging is driven by `tasks/scripts/stage-prebuilt-binaries.sh`. Because
staging cross-compiles on the host, it sources `tasks/scripts/build-env.sh` and
raises the per-process open-file limit before invoking `cargo zigbuild` on
macOS — the static musl link opens hundreds of `.rlib` files at once and would
otherwise fail with `ProcessFdQuotaExceeded` under macOS's default soft limit of
256. The guard is a no-op on Linux and when `cargo-zigbuild` is absent. Gateway
binaries use `cargo zigbuild` with GNU targets pinned to glibc 2.28, including
native-architecture builds, so the gateway image, standalone tarballs, and Linux
packages share the same host portability floor. The gateway build enables
`bundled-z3`. Linux VM driver release artifacts use the same glibc floor so
package-managed VM support does not raise the package runtime requirement.
Gateway staging and release workflows set up the Zig C/C++ wrapper before
bundled Z3 builds and verify the maximum referenced `GLIBC_*` symbol version
before publishing or copying artifacts.
Supervisor binaries remain static musl and use `cargo zigbuild` when available,
including native CPU architectures, so C dependencies are compiled for the musl
target instead of the host GNU libc target. Local Docker image tasks infer the
target architecture from `DOCKER_PLATFORM` when set. Otherwise, they require
valid container engine host metadata and fail when the engine query is
unavailable or reports an unsupported architecture, avoiding host-kernel
fallbacks that can target the wrong architecture. CI invokes the same staging
step via the `rust-native-build.yml` workflow (per-architecture, per-component)
and uploads the result as an artifact that the image build job downloads back
into the staging directory before running Buildx.

Runtime layout:

- **Gateway**: `gcr.io/distroless/cc-debian13:nonroot` base, GNU-linked binary at
  `/usr/local/bin/openshell-gateway`, runs as UID/GID `1000:1000`. Linux GNU
  gateway binaries must not reference `GLIBC_*` symbols newer than
  `GLIBC_2.28`; release workflows verify this before publishing artifacts. The
  gateway bundles z3, so the image does not need a distro-provided z3 runtime.
- **VM driver**: host GNU-linked binary installed at
  `/usr/libexec/openshell/openshell-driver-vm` in Linux packages and published
  as a release artifact. Linux GNU VM driver binaries must not reference
  `GLIBC_*` symbols newer than `GLIBC_2.28`; release workflows verify this
  before publishing artifacts.
- **Supervisor**: Alpine base with `nftables`, static musl binary at
  `/openshell-sandbox`. Static linkage keeps the binary usable when the image
  is mounted/extracted into sandbox environments (Docker extraction, Podman
  image volumes, Kubernetes init-container copy-self), while `nftables` supports
  Kubernetes supervisor sidecar egress enforcement.

Gateway image builds bake the corresponding supervisor image tag into the
gateway binary so Docker sandboxes do not depend on `:latest` by default.
The Helm chart omits the supervisor image from gateway configuration unless an
operator supplies a repository or tag override, preserving that build-time
pairing for Kubernetes sandboxes as well.
Package formulas also pin Docker supervisor extraction to the matching release
image tag so standalone gateway binaries do not infer image tags from package
versions.
The Homebrew service keeps gateway TLS under the Homebrew state directory but
mirrors Docker sandbox client TLS into `$HOME/.local/state/openshell/homebrew/tls`
at service start, because Docker Desktop bind mounts must use paths visible to
the macOS user's shared home directory.

Local image work should use `mise` tasks rather than direct Docker commands so
the same staging and tagging assumptions are used locally and in CI.

Container-engine selection is centralized in `tasks/scripts/container-engine.sh`.
`CONTAINER_ENGINE=docker|podman` is the only explicit override. Docker- and
Podman-backed e2e wrappers validate that override against their lane, set
`OPENSHELL_E2E_DRIVER`, and reject the removed
`OPENSHELL_E2E_CONTAINER_ENGINE` selector so build helpers and Rust e2e support
containers use the same engine. When no explicit override is present, an e2e
driver requirement wins, then a local-cluster requirement, then host
auto-detection.

Local Kubernetes image workflows opt into cluster-aware selection with
`CONTAINER_ENGINE_TARGET=local-k8s-cluster`. The hint is intentionally scoped to
Skaffold-style `push: false` builds where the image must land in the engine
backing the active local cluster: `k3d-*` contexts require Docker, `kind-*`
contexts use `KIND_EXPERIMENTAL_PROVIDER=docker|podman` when set, and ambiguous
or unknown contexts require an explicit `CONTAINER_ENGINE`. Other image builds
do not infer from kube context.

## Disposable Test Guests

The Nix test guest harness under `nix/test-guest` boots native-architecture cloud images
through QEMU for package, release, and E2E validation. A prepared cache entry is
captured after the exact ordered Ansible configuration list and before
test-specific packages, copied binaries, forwarded ports, or commands.

Prepared disks are flattened, sanitized QCOW2 images. The local cache keeps them
read-only and each test receives a fresh writable overlay and cloud-init
identity. The optional shared cache stores the compressed standalone disk and
its compatibility metadata as a custom OCI artifact. Normal test runs ensure
the exact local entry exists, invoking the cache builder automatically on a
miss before booting a disposable overlay. The separate cache app owns OCI
pulls and explicit publication. OCI pulls require a trusted manifest digest
and retain that provenance with the local entry; mutable tags are used only
for explicit publication.

## Python Wheel Packaging

The generated protobuf/gRPC stubs under `python/openshell/_proto/` are gitignored
build outputs of `mise run python:proto`. The task uses `uv run --frozen` to
synchronize the current worktree's `.venv` from `uv.lock` before generation.
maturin honors `.gitignore` when collecting `python-source` files, so native
builds (Linux CI, local `pip install .`) would drop them and ship an unimportable
wheel. `pyproject.toml`
pins them back in with `[tool.maturin].include` globs. The release workflows
install each Linux wheel in a clean image and import `openshell.sandbox` as a
smoke check.

## CI and E2E

Required checks run on GitHub Actions. Workflows that use NVIDIA self-hosted runners trigger from copy-pr-bot mirror branches, so trusted PRs are mirrored into `pull-request/<N>` branches before those workflows run. `main` also uses GitHub merge queue so the final queued integration commit is validated before it merges.

The high-level CI model:

1. PR-context gate jobs publish required statuses for the PR head commit.
2. Standard branch checks run from trusted mirror branches.
3. Label-gated Docker, Podman, VM, GPU, and Kubernetes E2E checks run from
   trusted mirror branches.
4. Merge-group checks run against GitHub's temporary queue branch for the final integration state.
5. Gate jobs verify that the mirror branch matches the PR head, or that the merge-group workflow ran for the queued SHA, and that the expected non-gate workflow actually ran.
6. Release workflows rebuild and publish binaries, wheels, images, and docs.

Repository CI keeps telemetry compiled into release-parity artifacts but
disables emission for Rust tests, E2E runs, and release canaries. This prevents
synthetic activity from contributing to product usage metrics.

See `CI.md` for the contributor workflow, labels, and maintainer merge-queue workflow.

## Docs Site

Published docs live in `docs/`. Navigation lives in `docs/index.yml`. Fern site
configuration, components, theme assets, and publish settings live in `fern/`.

Use `mise run docs` for strict validation and `mise run docs:serve` for local
preview. PR previews are produced by `.github/workflows/branch-docs.yml` when
Fern credentials are available. Production docs publish from the release tag
workflow.

## Validation Expectations

- Run `mise run pre-commit` before committing.
- Run `mise run test` after code changes.
- Run `mise run e2e` for sandbox, policy, driver, or deployment changes when the
  affected runtime can be exercised.
- Run `mise run ci` before opening a PR when practical.
- Run `mise run docs` when `docs/` or `fern/` changes.

Architecture-only changes should still check links and references because this
directory is used by agents during implementation and review.
