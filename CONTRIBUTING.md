# Contributing to NemoClaw

## Prerequisites

Install [mise](https://mise.jdx.dev/). This is used to set up the development environment.

```bash
# Install mise (macOS/Linux)
curl https://mise.run | sh
```

After installing `mise`, activate it with `mise activate` or [add it to your shell](https://mise.jdx.dev/getting-started.html).

Shell setup examples:

```bash
# Fish
echo '~/.local/bin/mise activate fish | source' >> ~/.config/fish/config.fish

# Zsh
echo 'eval "$(~/.local/bin/mise activate zsh)"' >> ~/.zshrc
```

Project requirements:

- Rust 1.88+
- Python 3.12+
- Docker (running)

## Getting Started

```bash
# One-time trust
mise trust

# Launch a sandbox (deploys a cluster if one isn't running)
mise run sandbox
```

## `nemoclaw` Shortcut

Inside this repository, `nemoclaw` is a local shortcut script at `scripts/bin/nemoclaw`. The script will

1. Builds `navigator-cli` if needed.
2. Runs the local debug CLI binary (`target/debug/nemoclaw`).

Because `mise` adds `scripts/bin` to `PATH` for this project, you can run `nemoclaw` directly from the repo.

```bash
nemoclaw --help
nemoclaw sandbox create -- codex
```

## Main Tasks

These are the primary `mise` tasks for day-to-day development:

| Task               | Purpose                                                 |
| ------------------ | ------------------------------------------------------- |
| `mise run cluster` | Bootstrap or incremental deploy                         |
| `mise run sandbox` | Create a sandbox on the running cluster                 |
| `mise run test`    | Default test suite                                      |
| `mise run e2e`     | Default end-to-end test lane                            |
| `mise run ci`      | Full local CI checks (lint, compile/type checks, tests) |
| `mise run clean`   | Clean build artifacts                                   |

## Project Structure

```
crates/
├── navigator-core/      # Core library
├── navigator-server/    # Main gateway server, ingress for all operations
├── navigator-sandbox/   # Sandbox execution environment
├── navigator-bootstrap/ # Local cluster bootstrap (Docker)
└── navigator-cli/       # Command-line interface
python/                  # Python bindings
proto/                   # Protocol buffer definitions
architecture/            # Architecture documentation and design plans
build/                   # mise task definitions and build scripts
├── *.toml               # Task includes (loaded by mise.toml task_config)
└── scripts/             # Shared build scripts used by tasks
deploy/
├── docker/              # Dockerfiles and build artifacts
├── helm/navigator/      # NemoClaw Helm chart
└── kube/manifests/      # Kubernetes manifests for k3s auto-deploy
```

## Development Workflow

### Building

```bash
mise run build           # Debug build
mise run build:release   # Release build
mise run check           # Quick compile check
```

### Testing

```bash
mise run test            # All tests (Rust + Python)
mise run test:rust       # Rust tests only
mise run test:python     # Python tests only
mise run test:e2e:sandbox # Sandbox Python e2e tests
```

### Python E2E Test Patterns

- Put sandbox SDK e2e tests in `e2e/python/`.
- Prefer `Sandbox.exec_python(...)` with Python callables over inline `python -c` strings.
- Define callable helpers inside the test function when possible so they serialize cleanly in sandbox.
- Keep scenarios focused: one test for happy path and separate tests for negative/policy enforcement behavior.
- Use `mise run test:e2e:sandbox` to run this suite locally.

### Linting & Formatting

```bash
# Rust
mise run rust:format         # Format code
mise run rust:format:check   # Check formatting
mise run rust:lint           # Lint with Clippy

# Python
mise run python:format   # Format with ruff
mise run python:lint     # Lint with ruff
mise run python:typecheck # Type check with ty

# Helm
mise run helm:lint       # Lint the nemoclaw helm chart
```

### Running Components

```bash
mise run sandbox         # Run sandbox container with interactive shell
```

### Custom Container Images

Use `--from` to run a sandbox with any Linux container image, a community sandbox, or a
local Dockerfile:

```bash
# Use a community sandbox image
ncl sandbox create --from openclaw

# Run an interactive shell in an Ubuntu sandbox
ncl sandbox create --from ubuntu:24.04

# Run a command in a custom image
ncl sandbox create --from python:3.12-slim -- python3 -c "print('hello')"

# Sync local files and run in a custom image
ncl sandbox create --from node:22 --sync -- npm test

# Build from a local Dockerfile in one step
ncl sandbox create --from ./Dockerfile

# Build from a directory containing a Dockerfile
ncl sandbox create --from ./my-sandbox/
```

The `--from` flag accepts community sandbox names (e.g., `openclaw`), paths to Dockerfiles
or directories, and full container image references. See `architecture/sandbox-custom-containers.md`
for the full resolution heuristic.

The supervisor binary is side-loaded from the standard sandbox image via a Kubernetes init
container. The default `run_as_user`/`run_as_group` policy is cleared for custom images to
avoid failures on images that lack the `sandbox` user. See `architecture/sandbox.md` for
details on the bootstrap flow and constraints.

#### Building and Pushing Custom Images (Manual Two-Step)

Use `ncl sandbox image push` to build a Dockerfile and push the resulting image into the
cluster's containerd runtime separately (the `--from` flag does this automatically for
Dockerfile paths):

```bash
# Build and push from a Dockerfile
ncl sandbox image push --dockerfile ./Dockerfile

# Specify a custom tag
ncl sandbox image push --dockerfile ./Dockerfile --tag my-sandbox:latest

# Specify a build context directory
ncl sandbox image push --dockerfile ./build/Dockerfile --context ./build

# Pass build arguments
ncl sandbox image push --dockerfile ./Dockerfile --build-arg PYTHON_VERSION=3.12

# Use the pushed image
ncl sandbox create --from my-sandbox:latest
```

The command builds the image using the local Docker daemon and pushes it into the cluster
via the same `docker save` / `ctr images import` pipeline used for component images. A
`.dockerignore` file in the build context directory is respected.

### Git Hooks (Pre-commit)

We use `mise generate git-pre-commit` for local pre-commit checks.

Generate a Git pre-commit hook that runs the `pre-commit` task:

```bash
mise generate git-pre-commit --write --task=pre-commit
```

### Kubernetes Development

The project uses the NemoClaw CLI to provision a local k3s-in-container cluster. Docker is the only external dependency for cluster bootstrap.

```bash
mise run cluster          # Recreate local cluster quickly using prebuilt images
mise run cluster:build    # Build component images, then deploy cluster (CI-friendly)
mise run cluster:deploy   # Fast deploy: rebuild changed components and skip unnecessary helm work
mise run cluster:deploy:sandbox # Fast deploy sandbox-only changes
mise run cluster:push:server    # Push local server image to configured pull registry
mise run cluster:push:sandbox   # Push local sandbox image to configured pull registry
mise run cluster:deploy:pull    # Force full pull-mode deploy flow
mise run cluster:push           # Legacy image-import fallback workflow
```

`mise run cluster` uses local `.env` values when present and appends missing keys:
`CLUSTER_NAME`, `GATEWAY_PORT`, and `NEMOCLAW_CLUSTER`.
If `GATEWAY_PORT` is missing, it picks a free local port and persists it to `.env`.
Existing `.env` values are not overwritten.
Fast `mise run cluster` flow:
1. Recreate cluster.
2. Ensure local registry (`127.0.0.1:5000`) is running in pull-through-cache mode.
3. Deploy with local image refs (`127.0.0.1:5000/navigator/*`, tag `latest` unless `IMAGE_TAG` is set) while k3s pulls through `host.docker.internal:5000`.
4. Use `mise run cluster:deploy` (or `cluster:deploy:sandbox`) to push local changes to that registry and redeploy only relevant components.

This keeps iterative local push workflows working while still caching remote pulls.
`mise run cluster:build` keeps the local build-and-push flow for development/CI.
Cluster bootstrap pulls the cluster image from the published remote registry by default.
Set `NEMOCLAW_CLUSTER_IMAGE` to override the image reference explicitly.

Default local cluster workflow uses pull mode with a local Docker registry at `127.0.0.1:5000`.
Local clusters also bind host port `6443` for the Kubernetes API, so only one
local NemoClaw cluster can run at a time on a given Docker host.
You can override repository settings with:

- `IMAGE_REPO_BASE` (for example `127.0.0.1:5000/navigator`)
- `NEMOCLAW_REGISTRY_HOST`, `NEMOCLAW_REGISTRY_NAMESPACE`
- `NEMOCLAW_REGISTRY_ENDPOINT` (optional mirror endpoint override, e.g. `host.docker.internal:5000`)
- `NEMOCLAW_REGISTRY_USERNAME`, `NEMOCLAW_REGISTRY_PASSWORD`
- `NEMOCLAW_REGISTRY_INSECURE=true|false`

Useful env flags for fast deploy:

- `FORCE_HELM_UPGRADE=1` - run Helm upgrade even when chart files are unchanged
- `DEPLOY_FAST_HELM_WAIT=1` - wait for Helm upgrade completion (`helm --wait`)
- `DEPLOY_FAST_MODE=full` - force full component rebuild behavior through fast deploy
- `DOCKER_BUILD_CACHE_DIR=.cache/buildkit` - local BuildKit cache directory used by component image builds

GitHub Container Registry mapping (CI or shared dev):

```bash
export NEMOCLAW_REGISTRY_HOST=ghcr.io
export NEMOCLAW_REGISTRY_NAMESPACE=${GITHUB_REPOSITORY}
export NEMOCLAW_REGISTRY_USERNAME=${GITHUB_ACTOR}
export NEMOCLAW_REGISTRY_PASSWORD=${GITHUB_TOKEN}
export IMAGE_REPO_BASE=ghcr.io/${GITHUB_REPOSITORY}
```

The cluster exposes ports 80/443 for gateway traffic and 6443 for the Kubernetes API.

Once the cluster is deployed. You can interact with the cluster using standard `ncl` CLI commands.

### Gateway mTLS for CLI

When the cluster is configured to terminate TLS at the Gateway with client authentication, the
CLI needs the generated client certificate bundle. The chart creates a `navigator-cli-client`
Secret containing `ca.crt`, `tls.crt`, and `tls.key`. During `ncl cluster admin deploy`, the
CLI bundle is automatically copied into `~/.config/nemoclaw/clusters/<name>/mtls`, where
`<name>` comes from `NEMOCLAW_CLUSTER_NAME` or the host in `NEMOCLAW_CLUSTER` (localhost
defaults to `nemoclaw`).

### Debugging Cluster Issues

If a cluster fails to start or is unhealthy after `ncl cluster admin deploy`, use the `debug-navigator-cluster` skill (located at `.agent/skills/debug-navigator-cluster/SKILL.md`) to diagnose the issue. This skill provides step-by-step instructions for troubleshooting cluster bootstrap failures, health check errors, and other infrastructure problems.

### Docker Build Tasks

```bash
mise run docker:build           # Build all Docker images
mise run docker:build:sandbox   # Build the sandbox Docker image
mise run docker:build:server    # Build the server Docker image
mise run docker:build:cluster   # Build the airgapped k3s cluster image
```

### Python Development

```bash
mise run python:dev      # Install Python package in development mode (builds CLI binary)
mise run python:build    # Build Python wheel with CLI binary
```

Python protobuf stubs in `python/navigator/_proto/` are generated artifacts and are gitignored
(except `__init__.py`). `mise` Python build/test/lint/typecheck tasks run `python:proto`
automatically, so you generally do not need to generate stubs manually.

### Publishing

Versions are derived from git tags using `setuptools_scm`. No version bumps need to be committed.
Python wheel builds inject version at build time via
`NEMOCLAW_CARGO_VERSION` (Cargo/SemVer), applied inside wheel-builder Docker
layers, so publish flows do not edit `Cargo.toml`/`Cargo.lock` in the working
tree.

**Version commands:**

```bash
mise run version:print             # Show computed versions (python, cargo, docker)
mise run version:print -- --cargo  # Show cargo version only
```

**Publishing credentials (one-time setup):**

```bash
echo "
NAV_PYPI_USERNAME=$USER
NAV_PYPI_PASSWORD=$ARTIFACTORY_PASSWORD" >> .env
```

Docker publishing in CI uses AWS credentials for ECR. Python publishing uses a
two-stage flow: wheels are uploaded to S3, then an internal-network runner
publishes them to Artifactory with `NAV_PYPI_*` credentials.

**Main branch publish (CI):**

- Publishes Docker multiarch images to ECR as `:dev`, `:latest`, and a versioned dev tag.
- Builds Linux + macOS (arm64) Python wheels and uploads them to
  `s3://navigator-pypi-artifacts/navigator/<wheel-version>/`.
- Runs a publish job on the `nv` runner to list that version prefix, download
  the wheels, and publish them to Artifactory.

**Tag release publish (CI):**

- Push a semver tag (`vX.Y.Z`) to trigger release jobs.
- CI publishes Docker multiarch images to ECR as `:X.Y.Z` (no `:latest`).
- CI stages Linux + macOS (arm64) Python wheels in S3 and publishes to
  Artifactory from the `nv` runner.

**Tagging a release:**

```bash
git tag v0.1.1
git push --tags
# CI will build and publish Docker + Linux/macOS Python wheels.
```

**Local macOS wheel publish (arm64):**

```bash
# Native on macOS host:
mise run python:publish:macos

# Cross-compile from Linux via Docker:
mise run python:build:macos:docker
```

### Cleaning

```bash
mise run clean           # Clean build artifacts
```

## Code Style

• **Rust**: Formatted with `rustfmt`, linted with Clippy (pedantic + nursery)
• **Python**: Formatted and linted with `ruff`, type-checked with `ty`

Run `mise run all` before committing to check everything (runs `fmt:check`, `clippy`, `test`, `python:lint`).

## CLI Output Style

When printing structured output from CLI commands, follow these conventions:

• **Blank line after headings**: Always print an empty line between a heading and its key-value fields. This improves readability in the terminal.
• **Indented fields**: Key-value fields should be indented with 2 spaces.
• **Dimmed keys**: Use `.dimmed()` for field labels (e.g., `"Id:".dimmed()`).
• **Colored headings**: Use `.cyan().bold()` for primary headings.

**Good:**

```
Created sandbox:

  Id: cddeeb6d-a4d3-4158-a4d1-bd931f743700
  Name: sandbox-cddeeb6d
  Namespace: navigator
```

**Bad** (no blank line after heading):

```
Created sandbox:
  Id: cddeeb6d-a4d3-4158-a4d1-bd931f743700
  Name: sandbox-cddeeb6d
  Namespace: navigator
```

## Commit Messages

This project uses [Conventional Commits](https://www.conventionalcommits.org/). All commit messages must follow the format:

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

**Types:**

- `feat` - New feature
- `fix` - Bug fix
- `docs` - Documentation only
- `chore` - Maintenance tasks (dependencies, build config)
- `refactor` - Code change that neither fixes a bug nor adds a feature
- `test` - Adding or updating tests
- `ci` - CI/CD changes
- `perf` - Performance improvements

**Examples:**

```
feat(cli): add --verbose flag to nemoclaw run
fix(sandbox): handle timeout errors gracefully
docs: update installation instructions
chore(deps): bump tokio to 1.40
```

### DCO

All contributions must include a `Signed-off-by` line in each commit message. This certifies you have the right to submit the work under the project license. See the [Developer Certificate of Origin](https://developercertificate.org/).

```bash
git commit -s -m "feat(sandbox): add new capability"
```

Use the `create-github-pr` skill to help with opening your pull request.
