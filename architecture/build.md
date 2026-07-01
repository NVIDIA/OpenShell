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

Binary staging is driven by `tasks/scripts/stage-prebuilt-binaries.sh`. Gateway
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

## Python Wheel Packaging

The generated protobuf/gRPC stubs under `python/openshell/_proto/` are gitignored
build outputs of `mise run python:proto`. maturin honors `.gitignore` when
collecting `python-source` files, so native builds (Linux CI, local
`pip install .`) would drop them and ship an unimportable wheel. `pyproject.toml`
pins them back in with `[tool.maturin].include` globs. The release workflows
install each Linux wheel in a clean image and import `openshell.sandbox` as a
smoke check.

## CI and E2E

Required checks run on GitHub Actions. Workflows that use NVIDIA self-hosted runners trigger from copy-pr-bot mirror branches, so trusted PRs are mirrored into `pull-request/<N>` branches before those workflows run.

The high-level CI model:

1. PR-context gate jobs publish required statuses for the PR head commit.
2. Standard branch checks run from trusted mirror branches.
3. Label-gated E2E, GPU, and Kubernetes checks run from trusted mirror branches.
4. Gate jobs verify that the mirror branch matches the PR head and that the expected non-gate workflow actually ran.
5. Release workflows rebuild and publish binaries, wheels, images, and docs.

See `CI.md` for the contributor workflow and labels.

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
