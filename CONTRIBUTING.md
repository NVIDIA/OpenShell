# Contributing to Navigator

## Prerequisites

Install [mise](https://mise.jdx.dev/). This is used to setup the development environment.

```bash
# Install mise (macOS/Linux)
curl https://mise.run | sh
```

After installing `mise` be sure to activate the environment by running `mise activate` or [add it to your shell](https://mise.jdx.dev/getting-started.html).

Shell installation examples:

Fish:

```bash
echo '~/.local/bin/mise activate fish | source' >> ~/.config/fish/config.fish
```

Zsh (Mac OS Default):

```bash
echo 'eval "$(~/.local/bin/mise activate zsh)"' >> ~/.zshrc
```

Project uses Rust 1.88+ and Python 3.12+.

## Getting started

```bash
# Install dependencies and build
mise install

# Build the project
mise build

# Run all project tests
mise test

# Run the CLI, this will build/run the cli from source (first run will be slow)
nav --help

# Run the sandbox
mise run sandbox

# Run the cluster
mise run cluster
```

## Sandbox SSH access

To connect to a running sandbox with SSH, use:

```bash
navigator sandbox connect <sandbox-id>
```

Relevant environment variables:

- `NAVIGATOR_SSH_GATEWAY_HOST`, `NAVIGATOR_SSH_GATEWAY_PORT`, `NAVIGATOR_SSH_CONNECT_PATH`
- `NAVIGATOR_SANDBOX_SSH_PORT`, `NAVIGATOR_SSH_HANDSHAKE_SECRET`, `NAVIGATOR_SSH_HANDSHAKE_SKEW_SECS`
- `NAVIGATOR_SSH_LISTEN_ADDR` (set inside sandbox pods)

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
├── helm/navigator/      # Navigator Helm chart
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
mise run fmt             # Format code
mise run fmt:check       # Check formatting
mise run clippy          # Run Clippy lints

# Python
mise run python:fmt      # Format with ruff
mise run python:lint     # Lint with ruff
mise run python:typecheck # Type check with ty

# Helm
mise run helm:lint       # Lint the navigator helm chart
```

### Running Components

```bash
mise run sandbox         # Run sandbox container with interactive shell
```

### Git Hooks (Pre-commit)

We use `mise generate git-pre-commit` for local pre-commit checks.

Generate a Git pre-commit hook that runs the `pre-commit` task:

```bash
mise generate git-pre-commit --write --task=pre-commit
```

### Kubernetes Development

The project uses the Navigator CLI to provision a local k3s-in-container cluster. Docker is the only external dependency for cluster bootstrap.

```bash
mise run cluster          # Build and deploy local k3s cluster with Navigator
mise run cluster:deploy   # Fast deploy: rebuild changed components and skip unnecessary helm work
mise run cluster:push:server    # Push local server image to configured pull registry
mise run cluster:push:sandbox   # Push local sandbox image to configured pull registry
mise run cluster:push:pki-job   # Push local pki-job image to configured pull registry
mise run cluster:deploy:pull    # Force full pull-mode deploy flow
mise run cluster:push           # Legacy image-import fallback workflow
```

Default local cluster workflow uses pull mode with a local Docker registry at `127.0.0.1:5000`.
You can override repository settings with:

- `IMAGE_REPO_BASE` (for example `127.0.0.1:5000/navigator`)
- `NAVIGATOR_REGISTRY_HOST`, `NAVIGATOR_REGISTRY_NAMESPACE`
- `NAVIGATOR_REGISTRY_ENDPOINT` (optional mirror endpoint override, e.g. `host.docker.internal:5000`)
- `NAVIGATOR_REGISTRY_USERNAME`, `NAVIGATOR_REGISTRY_PASSWORD`
- `NAVIGATOR_REGISTRY_INSECURE=true|false`

Useful env flags for fast deploy:

- `FORCE_HELM_UPGRADE=1` - run Helm upgrade even when chart files are unchanged
- `DEPLOY_FAST_HELM_WAIT=1` - wait for Helm upgrade completion (`helm --wait`)
- `DEPLOY_FAST_MODE=full` - force full component rebuild behavior through fast deploy
- `DOCKER_BUILD_CACHE_DIR=.cache/buildkit` - local BuildKit cache directory used by component image builds

GitLab Container Registry mapping (CI or shared dev):

```bash
export NAVIGATOR_REGISTRY_HOST=${CI_REGISTRY}
export NAVIGATOR_REGISTRY_NAMESPACE=${CI_PROJECT_PATH}
export NAVIGATOR_REGISTRY_USERNAME=${CI_REGISTRY_USER}
export NAVIGATOR_REGISTRY_PASSWORD=${CI_REGISTRY_PASSWORD}
export IMAGE_REPO_BASE=${CI_REGISTRY}/${CI_PROJECT_PATH}
```

The cluster exposes ports 80/443 for gateway traffic and 6443 for the Kubernetes API.

Once the cluster is deployed. You can interact with the cluster using standard `nav` CLI commands.

### Gateway mTLS for CLI

When the cluster is configured to terminate TLS at the Gateway with client authentication, the
CLI needs the generated client certificate bundle. The chart creates a `navigator-cli-client`
Secret containing `ca.crt`, `tls.crt`, and `tls.key`. During `nav cluster admin deploy`, the
CLI bundle is automatically copied into `~/.config/navigator/clusters/<name>/mtls`, where
`<name>` comes from `NAVIGATOR_CLUSTER_NAME` or the host in `NAVIGATOR_CLUSTER` (localhost
defaults to `navigator`).

### Debugging Cluster Issues

If a cluster fails to start or is unhealthy after `nav cluster admin deploy`, use the `debug-navigator-cluster` skill (located at `.agent/skills/debug-navigator-cluster/SKILL.md`) to diagnose the issue. This skill provides step-by-step instructions for troubleshooting cluster bootstrap failures, health check errors, and other infrastructure problems.

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

**Version commands:**

```bash
mise run version:print             # Show computed versions (python, cargo, docker)
mise run version:print -- --cargo  # Show cargo version only
mise run version:set               # Update Cargo.toml with git-derived version (or specified with --version)
mise run version:reset             # Restore Cargo.toml to git state
```

**Publishing credentials (one-time setup):**

```bash
echo "
NAV_PYPI_USERNAME=$USER
NAV_PYPI_PASSWORD=$ARTIFACTORY_PASSWORD" >> .env
```

Docker publishing in CI uses AWS credentials for ECR. Python publishing uses
`NAV_PYPI_*` credentials for Artifactory.

**Main branch publish (CI):**

- Publishes Docker multiarch images to ECR as `:dev`, `:latest`, and a versioned dev tag.

**Tag release publish (CI):**

- Push a semver tag (`vX.Y.Z`) to trigger release jobs.
- CI publishes Docker multiarch images to ECR as `:X.Y.Z` (no `:latest`).
- CI publishes Linux + macOS (arm64) Python wheels to Artifactory and creates GitLab release notes.

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
feat(cli): add --verbose flag to nav run
fix(sandbox): handle timeout errors gracefully
docs: update installation instructions
chore(deps): bump tokio to 1.40
```

## Pull Requests

1. Create a feature branch from `main`
2. Make your changes with tests
3. Run `mise run all` to verify
4. Open a PR with a clear description

Use the `create-gitlab-mr` skill to help with opening your pull request.
