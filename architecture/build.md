# Build

This page records the stable build, CI, docs, and release architecture. It is
not a command reference. Contributor-facing workflow details live in
`CONTRIBUTING.md`, `CI.md`, and published docs.

## Artifacts

OpenShell builds these main artifacts:

| Artifact | Source |
|---|---|
| Gateway binary | `crates/openshell-server` |
| CLI binaries and system packages | `crates/openshell-cli` plus release packaging |
| E2E conformance CLI | `crates/openshell-conformance-cli` |
| Python SDK wheel | `python/openshell` |
| TypeScript SDK package | `sdk/typescript` |
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

Building a binary without the `telemetry` feature compiles out telemetry
entirely: no endpoint, no telemetry HTTP client, and no emission code. With
telemetry compiled out, `telemetry::enabled()` is always `false` and the
`emit_*` helpers are no-ops, so the data-model types stay available and
dependent crates compile unchanged. The runtime `OPENSHELL_TELEMETRY_ENABLED`
switch remains the way to disable telemetry in a default (telemetry-enabled)
build.

Cargo cannot subtract a single default feature, so each of the three binary
crates also defines a `defaults-without-telemetry` alias listing every default
except `telemetry`. Telemetry-free builds use
`--no-default-features --features defaults-without-telemetry` and stay correct
as the default set grows, instead of dropping unrelated defaults the way a bare
`--no-default-features` does on `openshell-sandbox`. The alias is a keep-list,
not a switch: enabling it on top of the defaults would otherwise yield a
telemetry-on binary that reads as telemetry-free, so each crate root carries a
`compile_error!` for the `telemetry` + `defaults-without-telemetry` combination.
`rust:verify:defaults-without-telemetry` guards both properties — that each
alias still equals its crate's defaults minus `telemetry`, and that the
mutual-exclusion error is wired up — and `rust:verify:telemetry-off` builds
through the alias and inspects the resulting binaries for telemetry markers.

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

## Linux Runtime Environments

OpenShell uses different Linux libc environments for different host artifacts.
The standalone `openshell` CLI is built as a static musl binary so it can run on
a wide range of Linux distributions without depending on the host's glibc. Host
runtime binaries that use the GNU/Linux runtime environment are GNU-linked.
`openshell-gateway` and `openshell-driver-vm` are built with a glibc 2.28 floor.
The gateway bundles z3 into the release binary so Linux packages, standalone
tarballs, and gateway images do not depend on distro-specific z3 shared-library
SONAMEs.

The supervisor is the one binary whose libc is selectable, because it is the one
binary executed inside a userland OpenShell does not control. `SUPERVISOR_LIBC`
chooses between `musl` (default) and `glibc-static`. Both produce a fully static
binary; the choice does not change the runtime layout or the supervisor image base.
Static linkage is a hard requirement rather than a preference, so both variants
are verified by `tasks/scripts/verify-static-binary.sh`, which fails the build on
any `PT_INTERP` or `DT_NEEDED` entry.

The two variants differ only in build-time constraints:

| | `musl` (default) | `glibc-static` |
|---|---|---|
| Cross-compiles | yes, via `cargo zigbuild` | no — must build natively per architecture |
| Host requirement | zig + cargo-zigbuild | glibc static libraries (`glibc-static` on Fedora/RHEL, `libc6-dev` on Debian/Ubuntu) |
| libc license | MIT | LGPL-2.1-or-later, statically linked |

`cargo zigbuild` cannot produce the `glibc-static` variant: `zig cc` accepts
`-static` for `*-linux-gnu` targets and emits a dynamically linked binary
anyway. The staging script therefore refuses to cross-compile that variant
instead of silently degrading linkage.

Selecting `glibc-static` statically links LGPL glibc into a redistributed
binary, which carries relinking obligations that musl (MIT) does not. Treat the
default as the shipping configuration unless that has been reviewed.

## Container Builds

The Docker image pipeline is a two-step flow: build the Rust binary natively
for the target architecture, then assemble the container image from the
prebuilt binary. The gateway image is built from `deploy/docker/Dockerfile.gateway`
and the supervisor image from `deploy/docker/Dockerfile.supervisor`. Neither
Dockerfile compiles Rust — both copy a staged binary out of
`deploy/docker/.build/prebuilt-binaries/<arch>/` into the final image.

Local binary staging is driven by `tasks/scripts/stage-prebuilt-binaries.sh`. Because
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
Supervisor binaries are static in every configuration. The default `musl`
variant uses `cargo zigbuild` when available, including native CPU
architectures, so C dependencies are compiled for the musl target instead of the
host GNU libc target. The `glibc-static` variant uses plain `cargo build` with
`+crt-static` and requires a native per-architecture build. Local Docker image tasks infer the
target architecture from `DOCKER_PLATFORM` when set. Otherwise, they require
valid container engine host metadata and fail when the engine query is
unavailable or reports an unsupported architecture, avoiding host-kernel
fallbacks that can target the wrong architecture. CI instead compiles binaries
in platform-specific Nix development shells through reusable workflows and the
shared `build-rust-binary` action. The image build downloads each binary artifact
into the staging directory before running Buildx.

Gateway and supervisor binaries staged into branch E2E, Release Dev, and Release
Tag images are compiled through `cargo auditable` (pinned in `mise.toml`), which
embeds a `.dep-v0` section describing the Rust dependencies actually compiled
into the binary. That section holds data rather than symbols, so it survives the
workspace's `strip = true` release profile, and Syft can catalog the crates
present in image binaries instead of inferring them from the source tree. This
is a different artifact from the source SBOM produced by `syft dir:.` in
`tasks/sbom.toml`, which describes the checkout, and from the image SBOM
attestation below, which describes a published image.

The shared binary build action compiles release artifacts with `cargo auditable`.
Branch E2E, Release Dev, and Release Tag image jobs stage those same artifacts
instead of rebuilding binaries in Docker. Each binary build scans its output with
Syft and requires at least one decoded Cargo package before uploading the
artifact. Darwin builds replace Nix's `libiconv` load command with the macOS
system install name, ad-hoc sign the modified binary, and fail if `otool -L`
reports any remaining `/nix/store` dependency. Runtime and Syft verification
run after that normalization. The CI image gains the pinned `cargo-auditable`
tool through `mise install --locked` but ships no auditable OpenShell binary of
its own.

Pushed Docker images carry minimal SLSA provenance and a per-platform SPDX SBOM
generated by BuildKit's default Syft scanner. The registry exporter uses OCI
media types and `oci-artifact=true`, so each attestation identifies its subject.
GHCR exposes these through the image index because it has no referrers API.

Attestations require a registry-backed image index. Local builds therefore keep
`--provenance=false`, and Podman builds carry neither attestation.
`tasks/scripts/verify-image-sbom.sh` verifies the merged multi-arch tag and runs
with `--require-cargo` for auditable builds, so those attestations must also
contain Cargo packages.

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
  before publishing artifacts. Nix produces the platform-specific compressed
  runtime inputs. CI combines them with the matching supervisor artifact in a
  runner-temporary directory outside Cargo's `target/` before the shared Rust
  cache action runs. An explicitly configured VM runtime bundle is required to
  contain every non-empty embedding input; the driver build fails before
  packaging when an input is absent or empty.
- **Supervisor**: Alpine base with `nftables`, static binary at
  `/openshell-sandbox` (musl by default; see `SUPERVISOR_LIBC` above). Static
  linkage keeps the binary usable when the image is mounted/extracted into
  sandbox environments (Docker extraction, Podman image volumes, Kubernetes
  init-container copy-self), whose libc and glibc version are not known at build
  time, while `nftables` supports Kubernetes supervisor sidecar egress
  enforcement. The VM driver bundles its own supervisor build
  (`tasks/scripts/vm/build-supervisor-bundle.sh`) and does not read
  `SUPERVISOR_LIBC`.

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
build outputs of `mise run python:proto`. Setuptools includes them through the
package-data configuration in `pyproject.toml`. Release workflows build the
wheel directly and do not produce a source distribution. Setuptools SCM derives
local versions from Git and accepts the release workflow's computed version
through its distribution-specific override.

The build produces one platform-independent `py3-none-any` wheel. A verifier
checks its tag, metadata, version, required package files, and the absence of
native files or an `openshell` executable entry point. Release workflows build
the wheel once, install it in a clean virtual environment, import the public
package modules, and confirm that installation did not create an `openshell`
command.

## TypeScript SDK Packaging

The native TypeScript SDK in `sdk/typescript` uses Connect over the generated
OpenShell protobuf surface. `sdk/typescript/buf.gen.yaml` selects the client
proto closure, and `mise run sdk:ts:proto` generates gitignored sources under
`src/gen`. TypeScript compilation includes those sources in `dist`, so package
consumers do not run code generation.

Branch checks run `mise run sdk:ts:ci`, enforce an 80% line-coverage floor, and
exercise version stamping plus `npm publish --dry-run`. Tagged releases publish
`@nvidia/openshell-sdk` to GitHub Packages. The repository keeps package version
`0.0.0`; the release task derives and temporarily stamps the npm version from
the release tag.

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

Static security checks are deliberately outside the mirror-branch path. They run
directly on GitHub-hosted runners and none of them consume NVIDIA self-hosted
capacity. The change-oriented ones receive no secrets, so they also cover fork
pull requests; Codex Security release qualification is the exception because it
needs a scoped API key. That key routes Codex Security's model calls to
NVIDIA-hosted inference; the job itself still runs on a GitHub-hosted runner and
uses no NVIDIA self-hosted runner. Scanner jobs request `security-events: write`
and upload SARIF to Code Scanning directly on every event they run on, including
fork and Dependabot pull requests, which Code Scanning permits for
`pull_request` runs despite their read-only `GITHUB_TOKEN`. No privileged
intermediate workflow relays those uploads. Report retention differs by scanner:
Actionlint, Zizmor, and CodeQL keep their reports as workflow artifacts, and
Codex Security keeps no raw report.
Triggers differ by workflow: `.github/workflows/workflow-security.yml` runs on
`pull_request`, `merge_group`, `main`, and a weekly schedule;
`.github/workflows/dependency-review.yml` runs on `pull_request` and
`merge_group` only, because it needs a base and head commit to compare;
`.github/workflows/codeql.yml` runs nightly on the default branch (`main`) via
`schedule`, with `workflow_dispatch` kept for manual diagnostics; and
`.github/workflows/codex-security.yml` runs on pushed `v*.*.*-pre.*` tags, and is
also callable through `workflow_call` and `workflow_dispatch`. CodeQL does
not run on `pull_request`, `merge_group`, or pushes to `main`, so it reports
repository-level Code Scanning state on the default branch instead of per-PR
results, and its four-language matrix stays off the per-change critical path.
Codex Security is release-scoped rather than change-scoped, so it never runs on
a pull request or merge group.

- **Actionlint and Zizmor** analyze the workflow definitions themselves.
  Repository configuration lives in `.github/actionlint.yml` (self-hosted runner
  labels, scoped per-file ignores) and `.github/zizmor.yml` (scoped rule
  suppressions). Zizmor runs offline and reports only High severity, which is
  its maximum level. Both publish SARIF to Code Scanning and retain report
  artifacts. The Nix flake provides both scanners, so local runs use
  `nix develop --command actionlint -shellcheck= -pyflakes=` and
  `nix develop --command zizmor --offline --persona=regular --min-severity=high --no-exit-codes .`.
- **Dependency Review** compares the base and head dependency graphs. It
  preflights the GitHub Dependency Graph compare API and neutralizes itself with
  a warning while that repository feature is unavailable, so the check begins
  reporting on its own once the feature is enabled. Reviews run in warn-only
  mode.
- **CodeQL** analyzes product Rust code, examples, and the Go, Python, and
  TypeScript SDKs, scoped by `.github/codeql/codeql-config.yml`. Rust test code
  is excluded in two layers: the analyze job sets
  `CODEQL_EXTRACTOR_RUST_OPTION_CARGO_CFG_OVERRIDES=-test` so the extractor skips
  `#[cfg(test)]` blocks, and `paths-ignore` drops `crates/*/tests`, whose
  integration targets the cfg override does not reach. Examples remain in scope,
  and E2E test code stays excluded because `e2e/` is not an analyzed path. Only
  Go requires a build; the other languages use build mode `none`. Analysis runs
  on the nightly schedule or by manual dispatch. Results are uploaded to Code
  Scanning and always retained as workflow artifacts.
- **Codex Security** qualifies release candidates rather than individual
  changes. The job installs a pinned `@openai/codex-security` release into the
  runner temp directory before the repository is checked out and invokes it by
  absolute path, so repository-controlled files cannot shadow the scanner. Model
  calls go to NVIDIA-hosted inference at `https://inference-api.nvidia.com/v1`,
  declared as a custom Codex provider named `nvidia` that uses the Responses
  wire API with WebSockets disabled. The scan runs `openai/openai/gpt-5.6-sol`
  at `medium` reasoning effort. The `CODEX_SECURITY_API_KEY` secret holds the
  NVIDIA key and is exposed to the scan step alone, as `OPENAI_API_KEY` so the
  CLI selects API-key auth and as `NVIDIA_INFERENCE_API_KEY`, the provider
  `env_key` read by the Codex child process.
  `tasks/scripts/codex-security-release-range.mjs` resolves the scan range: the
  candidate must be a `vX.Y.Z-pre.N` tag that is an ancestor of `origin/main`,
  and the base is the newest stable `vX.Y.Z` tag merged into the candidate that
  is strictly older than the release train `vX.Y.Z` the candidate targets. A
  full-repository scan is only possible when no such stable tag exists and the
  caller passes `allow_full_bootstrap`. Each candidate scans the cumulative
  stable-to-candidate diff, so later candidates re-cover earlier ones. SARIF is
  uploaded against `refs/heads/main` at the candidate commit under the
  train-scoped category `codex-security/vX.Y.Z`, which makes each candidate's
  analysis replace the previous one for that train. Codex Security 0.1.24 cannot
  apply `--max-cost` to a slash-qualified model identifier, so the run has no
  CLI-enforced cost ceiling. Spend is bounded instead by the 120-minute job
  timeout, a single repository-wide concurrency group that serializes
  qualification so starting a newer candidate cancels an in-flight one, and
  NVIDIA account-side controls. No raw report is retained.

Findings never fail these checks; scanner and build failures do. A scanner that
cannot run, a CodeQL analyzer that does not complete, an unexpected Dependency
Graph API error, and a Codex Security range, scan, or export failure are all
errors, which keeps an informational check from silently degrading into a no-op.
Codex Security also rejects any scan scope other than the resolved
cumulative diff or an approved full bootstrap, so a qualification run either
covers the whole stable-to-candidate range or fails; a separate no-permission
job republishes the analysis job's outcome as the
`OpenShell / Codex Security (informational)` status. None of these checks are
required statuses, so they do not gate merges.

Codex Security findings are informational during the observation phase, and the
workflow only reports on candidates that already exist. Creating pre-release
tags and gating stable promotion on qualification results are part of
[RFC 0014](../rfc/0014-release-stability/release-qualification.md) and are not
implemented yet.

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
