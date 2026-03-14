# Contributing to OpenShell

OpenShell is built agent-first. We design systems and use agents to implement them. Your agent is your first collaborator — point it at this repo before opening issues, asking questions, or submitting code.

## Before You Open an Issue

This project ships with [agent skills](#agent-skills-for-contributors) that can diagnose problems, explore the codebase, generate policies, and walk you through common workflows. Before filing an issue:

1. Clone the repo and point your coding agent at it.
2. Load the relevant skill — `debug-openshell-cluster` for cluster problems, `openshell-cli` for usage questions, `generate-sandbox-policy` for policy help.
3. Have your agent investigate. Let it run diagnostics, read the architecture docs, and attempt a fix.
4. If the agent cannot resolve it, open an issue **with the agent's diagnostic output attached**. The issue template requires this.

### When to Open an Issue

- A real bug that your agent confirmed and could not fix.
- A feature proposal with a design — not a "please build this" request.
- An infrastructure problem that the `debug-openshell-cluster` skill could not resolve.
- Security vulnerabilities must follow [SECURITY.md](SECURITY.md) — **not** GitHub issues.

### When NOT to Open an Issue

- Questions about how things work — your agent can answer these from the codebase and architecture docs.
- Configuration problems — your agent can diagnose these with `openshell-cli` and `debug-openshell-cluster`.
- "How do I..." requests — the skills cover CLI usage, policy generation, TUI development, and more.

## Agent Skills for Contributors

Skills live in `.agents/skills/`. Your agent's harness can discover and load them natively. Here is the full inventory:

| Category | Skill | Purpose |
|----------|-------|---------|
| Getting Started | `openshell-cli` | CLI usage, sandbox lifecycle, provider management, BYOC workflows |
| Getting Started | `debug-openshell-cluster` | Diagnose cluster startup failures and health issues |
| Contributing | `create-spike` | Investigate a problem, produce a structured GitHub issue |
| Contributing | `build-from-issue` | Plan and implement work from a GitHub issue (maintainer workflow) |
| Contributing | `create-github-issue` | Create well-structured GitHub issues |
| Contributing | `create-github-pr` | Create pull requests with proper conventions |
| Reviewing | `review-github-pr` | Summarize PR diffs and key design decisions |
| Reviewing | `review-security-issue` | Assess security issues for severity and remediation |
| Reviewing | `watch-github-actions` | Monitor CI pipeline status and logs |
| Triage | `triage-issue` | Assess, classify, and route community-filed issues |
| Platform | `generate-sandbox-policy` | Generate YAML sandbox policies from requirements or API docs |
| Platform | `tui-development` | Development guide for the ratatui-based terminal UI |
| Maintenance | `sync-agent-infra` | Detect and fix drift across agent-first infrastructure files |
| Reference | `sbom` | Generate SBOMs and resolve dependency licenses |

### Workflow Chains

Skills connect into pipelines. Individual skill files don't describe these relationships.

- **Community inflow:** `triage-issue` → `create-spike` → `build-from-issue`
- **Internal development:** `create-spike` → `build-from-issue`
- **Security:** `review-security-issue` → `fix-security-issue`
- **Policy iteration:** `openshell-cli` → `generate-sandbox-policy`

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

## Building the `openshell` CLI

Inside this repository, `openshell` is a local shortcut script at `scripts/bin/openshell`. The script will

1. Build `openshell-cli` if needed.
2. Run the local debug CLI binary under `target/debug/openshell`.

Because `mise` adds `scripts/bin` to `PATH` for this project, you can run `openshell` directly from the repo.

```bash
openshell --help
openshell sandbox create -- codex
```

### Cluster debugging helpers

Two additional scripts in `scripts/bin/` provide gateway-aware wrappers for cluster debugging:

| Script | What it does |
|--------|-------------|
| `kubectl` | Runs `kubectl` inside the active gateway's k3s container via `openshell doctor exec` |
| `k9s` | Runs `k9s` inside the active gateway's k3s container via `openshell doctor exec` |

These work for both local and remote gateways (SSH is handled automatically). Examples:

```bash
kubectl get pods -A
kubectl logs -n openshell statefulset/openshell
k9s
k9s -n openshell
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
| `mise run docs`    | Build and serve documentation locally                   |
| `mise run clean`   | Clean build artifacts                                   |

## Project Structure

| Path            | Purpose                                       |
| --------------- | --------------------------------------------- |
| `crates/`       | Rust crates                                   |
| `python/`       | Python SDK and bindings                       |
| `proto/`        | Protocol buffer definitions                   |
| `tasks/`        | `mise` task definitions and build scripts     |
| `deploy/`       | Dockerfiles, Helm chart, Kubernetes manifests |
| `architecture/` | Architecture docs and plans                   |
| `.agents/`      | Agent skills and persona definitions          |

## Pull Requests

1. Create a feature branch from `main`.
2. Make your changes with tests.
3. Run `mise run ci` to verify.
4. Open a PR using the `create-github-pr` skill or manually following the [PR template](.github/PULL_REQUEST_TEMPLATE.md).

### Commit Messages

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
feat(cli): add --verbose flag to openshell run
fix(sandbox): handle timeout errors gracefully
docs: update installation instructions
chore(deps): bump tokio to 1.40
```

### DCO

All contributions must include a `Signed-off-by` line in each commit message. This certifies you have the right to submit the work under the project license. See the [Developer Certificate of Origin](https://developercertificate.org/).

```bash
git commit -s -m "feat(sandbox): add new capability"
```
