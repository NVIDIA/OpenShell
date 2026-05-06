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
| Gateway container image | `deploy/docker/Dockerfile.images` |
| Helm chart | `deploy/helm/openshell` |
| VM driver/runtime assets | `crates/openshell-driver-vm` and `crates/openshell-vm` |
| Published docs site | `docs/` rendered by Fern config in `fern/` |

Sandbox community images are built outside this repository.

## Container Builds

The Docker image pipeline stages prebuilt Rust binaries, then builds container
images from `deploy/docker/Dockerfile.images`. CI builds native artifacts on the
target architecture, stages them under `deploy/docker/.build/`, and then uses
Buildx to publish per-architecture images and multi-architecture tags.

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
