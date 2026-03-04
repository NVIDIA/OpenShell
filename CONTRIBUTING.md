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

# Start/recreate local cluster
mise run cluster

# Iterative deploy after code changes
mise run cluster:build

# Launch a sandbox
ncl sandbox create -- claude
```

## `ncl` Shortcut

Inside this repository, `ncl` is a local shortcut script at `scripts/bin/ncl`.

It:
1. Builds `navigator-cli` if needed.
2. Runs the local debug CLI binary (`target/debug/nemoclaw`).

Because `mise` adds `scripts/bin` to `PATH` for this project, you can run `ncl` directly from the repo.

```bash
ncl --help
ncl sandbox create -- codex
```

## Main Tasks

These are the primary `mise` tasks for day-to-day development:

| Task | Purpose |
|---|---|
| `mise run cluster` | Fast local cluster recreate |
| `mise run cluster:build` | Incremental deploy of changed components |
| `mise run cluster:sandbox` | Run sandbox container interactively |
| `mise run fmt` | Format Rust and Python |
| `mise run lint` | Repository lint checks |
| `mise run check` | Fast compile and type checks |
| `mise run test` | Default test suite |
| `mise run test:e2e` | Default end-to-end test lane |
| `mise run ci` | Full local CI checks |
| `mise run clean` | Clean build artifacts |
| `mise run version` | Print git-derived version |

## Project Structure

| Path | Purpose |
|---|---|
| `crates/navigator-core/` | Shared core library |
| `crates/navigator-server/` | Gateway/control plane server |
| `crates/navigator-sandbox/` | Sandbox runtime |
| `crates/navigator-bootstrap/` | Cluster bootstrap logic |
| `crates/navigator-cli/` | CLI implementation |
| `python/` | Python SDK/bindings |
| `proto/` | Protocol buffer definitions |
| `build/` | `mise` tasks and build scripts |
| `deploy/` | Dockerfiles, Helm chart, Kubernetes manifests |
| `architecture/` | Architecture docs and plans |

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
feat(cli): add --verbose flag to ncl run
fix(sandbox): handle timeout errors gracefully
docs: update installation instructions
chore(deps): bump tokio to 1.40
```

## Pull Requests

1. Create a feature branch from `main`
2. Make your changes with tests
3. Run `mise run ci` to verify
4. Open a PR with a clear description

### DCO

All contributions must include a `Signed-off-by` line in each commit message. This certifies you have the right to submit the work under the project license. See the [Developer Certificate of Origin](https://developercertificate.org/).

```bash
git commit -s -m "feat(sandbox): add new capability"
```

Use the `create-github-pr` skill to help with opening your pull request.
