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

## Container Builds

The Docker image pipeline is a two-step flow: build the Rust binary natively
for the target architecture, then assemble the container image from the
prebuilt binary. The gateway image is built from `deploy/docker/Dockerfile.gateway`
and the supervisor image from `deploy/docker/Dockerfile.supervisor`. Neither
Dockerfile compiles Rust — both copy a staged binary out of
`deploy/docker/.build/prebuilt-binaries/<arch>/` into the final image.

Binary staging is driven by `tasks/scripts/stage-prebuilt-binaries.sh`, which
runs `cargo build` natively on a matching host or `cargo zigbuild` when
cross-compiling. CI invokes the same staging step via the
`rust-native-build.yml` workflow (per-architecture, per-component) and uploads
the result as an artifact that the image build job downloads back into the
staging directory before running Buildx.

Runtime layout:

- **Gateway**: `nvcr.io/nvidia/distroless/cc` base, GNU-linked binary at
  `/usr/local/bin/openshell-gateway`, runs as UID/GID `65532:65532`.
- **Supervisor**: `scratch` base, static musl binary at `/openshell-sandbox`.
  Static linkage is required because the image is mounted/extracted into
  sandbox environments (Docker extraction, Podman image volumes, Kubernetes
  init-container copy-self) and cannot rely on a dynamic loader.

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

## CI and E2E

Required checks run on GitHub Actions. E2E and GPU workflows use NVIDIA
self-hosted runners, so trusted PRs are mirrored by copy-pr-bot into
`pull-request/<N>` branches before those workflows run.

The high-level CI model:

1. Standard branch checks run on normal PR activity.
2. Label-gated E2E and GPU checks run from trusted mirror branches.
3. Gate jobs verify that the expected non-gate workflow actually ran.
4. Release workflows rebuild and publish binaries, wheels, images, and docs.

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
