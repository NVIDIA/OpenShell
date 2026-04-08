# Contributing to OpenShell

OpenShell is built agent-first. We design systems and use agents to implement them. Your agent is your first collaborator — point it at this repo before opening issues, asking questions, or submitting code.

## The Critical Rule

**You must understand your code.** Using AI agents to write code is not just acceptable, it's how this project works. But you must be able to explain what your changes do and how they interact with the rest of the system. If you can't, don't submit it.

Submitting agent-generated code without understanding it — regardless of how clean it looks — wastes maintainer time and will result in your PR being closed. Repeat offenders will be blocked from the project.

## AI Usage

OpenShell is agent-first, not agent-only. The distinction matters:

- **Do** use agents to explore the codebase, run diagnostics, generate code, and iterate on implementations.
- **Do** use the skills in `.agents/skills/` — they exist to make your agent effective.
- **Do** interrogate your agent until you understand every edge case and interaction in your changes.
- **Don't** submit code you can't explain without your agent open.
- **Don't** use agents as a substitute for understanding the system. Read the architecture docs.

## First-Time Contributors

We use a vouch system. This exists because AI makes it trivial to generate plausible-looking but low-quality contributions, and we can no longer trust by default.

1. Open a [Vouch Request](https://github.com/NVIDIA/OpenShell/discussions/new?category=vouch-request) discussion.
2. Describe what you want to change and why.
3. Write in your own words. AI-generated vouch requests will be denied.
4. A maintainer will comment `/vouch` if approved.
5. Once vouched, you can submit pull requests.

**If you are not vouched, any pull request you open will be automatically closed.** Org members and collaborators with push access bypass this check.

### Finding Work

Issues labeled [`good-first-issue`](https://github.com/NVIDIA/OpenShell/issues?q=is%3Aissue+is%3Aopen+label%3Agood-first-issue) are scoped, well-documented, and friendly to new contributors. Start there. If you need guidance, comment on the issue.

All open issues are actionable — if it's in the issue tracker, it's ready to be worked on.

## Before You Open an Issue

This project ships with [agent skills](#agent-skills-for-contributors) that can diagnose problems, explore the codebase, generate policies, and walk you through common workflows. Before filing an issue:

1. Clone the repo and point your coding agent at it.
2. Load the relevant skill - `debug-openshell-cluster` for cluster problems, `debug-inference` for inference setup problems, `openshell-cli` for usage questions, `generate-sandbox-policy` for policy help.
3. Have your agent investigate. Let it run diagnostics, read the architecture docs, and attempt a fix.
4. If the agent cannot resolve it, open an issue **with the agent's diagnostic output attached**. The issue template requires this.

### When to Open an Issue

- A real bug that your agent confirmed and could not fix.
- A feature proposal with a design — not a "please build this" request.
- An infrastructure problem that the `debug-openshell-cluster` skill could not resolve.
- An inference setup problem that the `debug-inference` skill could not resolve.
- Security vulnerabilities must follow [SECURITY.md](SECURITY.md) — **not** GitHub issues.

### When NOT to Open an Issue

- Questions about how things work — your agent can answer these from the codebase and architecture docs.
- Configuration problems - your agent can diagnose these with `openshell-cli`, `debug-openshell-cluster`, and `debug-inference`.
- "How do I..." requests — the skills cover CLI usage, policy generation, TUI development, and more.

## Agent Skills for Contributors

Skills live in `.agents/skills/`. Your agent's harness can discover and load them natively. Here is the full inventory:

| Category        | Skill                     | Purpose                                                                                             |
| --------------- | ------------------------- | --------------------------------------------------------------------------------------------------- |
| Getting Started | `openshell-cli`           | CLI usage, sandbox lifecycle, provider management, BYOC workflows                                   |
| Getting Started | `debug-openshell-cluster` | Diagnose cluster startup failures and health issues                                                 |
| Getting Started | `debug-inference`         | Diagnose `inference.local`, host-backed local inference, and direct external inference setup issues |
| Contributing    | `create-spike`            | Investigate a problem, produce a structured GitHub issue                                            |
| Contributing    | `build-from-issue`        | Plan and implement work from a GitHub issue (maintainer workflow)                                   |
| Contributing    | `create-github-issue`     | Create well-structured GitHub issues                                                                |
| Contributing    | `create-github-pr`        | Create pull requests with proper conventions                                                        |
| Reviewing       | `review-github-pr`        | Summarize PR diffs and key design decisions                                                         |
| Reviewing       | `review-security-issue`   | Assess security issues for severity and remediation                                                 |
| Reviewing       | `watch-github-actions`    | Monitor CI pipeline status and logs                                                                 |
| Triage          | `triage-issue`            | Assess, classify, and route community-filed issues                                                  |
| Platform        | `generate-sandbox-policy` | Generate YAML sandbox policies from requirements or API docs                                        |
| Platform        | `tui-development`         | Development guide for the ratatui-based terminal UI                                                 |
| Documentation   | `update-docs`             | Scan recent commits and draft doc updates for user-facing changes                                   |
| Maintenance     | `sync-agent-infra`        | Detect and fix drift across agent-first infrastructure files                                        |
| Reference       | `sbom`                    | Generate SBOMs and resolve dependency licenses                                                      |

### Workflow Chains

Skills connect into pipelines. Individual skill files don't describe these relationships.

- **Community inflow:** `triage-issue` → `create-spike` → `build-from-issue`
- **Internal development:** `create-spike` → `build-from-issue`
- **Security:** `review-security-issue` → `fix-security-issue`
- **Policy iteration:** `openshell-cli` → `generate-sandbox-policy`

Workflow state labels use the `state:*` prefix, and security work uses `topic:security`. GitHub issue templates assign built-in issue types where applicable, and agent-created issues should use issue types or manual follow-up rather than type labels.

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

| Script    | What it does                                                                         |
| --------- | ------------------------------------------------------------------------------------ |
| `kubectl` | Runs `kubectl` inside the active gateway's k3s container via `openshell doctor exec` |
| `k9s`     | Runs `k9s` inside the active gateway's k3s container via `openshell doctor exec`     |

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
| `mise run docs`    | Build legacy Sphinx docs locally                        |
| `mise run clean`   | Clean build artifacts                                   |

## Project Structure

| Path            | Purpose                                       |
| --------------- | --------------------------------------------- |
| `crates/`       | Rust crates                                   |
| `python/`       | Python SDK and bindings                       |
| `proto/`        | Protocol buffer definitions                   |
| `tasks/`        | `mise` task definitions and build scripts     |
| `deploy/`       | Dockerfiles, Helm chart, Kubernetes manifests |
| `fern/`         | Published Fern docs site and MDX pages        |
| `docs/`         | Legacy Sphinx/MyST docs retained during transition |
| `architecture/` | Architecture docs and plans                   |
| `rfc/`          | Request for Comments proposals                |
| `.agents/`      | Agent skills and persona definitions          |

## RFCs

For cross-cutting architectural decisions, API contract changes, or process proposals that need broad consensus, use the RFC process. RFCs live in `rfc/` — copy the template, fill it in, and open a PR for discussion. See [rfc/README.md](rfc/README.md) for the full lifecycle and guidelines on when to write an RFC versus a spike issue or architecture doc.

## Documentation

If your change affects user-facing behavior (new flags, changed defaults, new features, bug fixes that contradict existing docs), update the relevant pages under `fern/pages/` in the same PR and adjust `fern/versions/latest.yml` if navigation changes. For explicit navbar entries, keep `page:` aligned with `sidebar-title` when present and put relative `slug:` values in `fern/versions/latest.yml`. Reserve frontmatter `slug` for folder-discovered pages or absolute URL overrides.

To ensure your doc changes follow NVIDIA documentation style, use the `update-docs` skill.
It scans commits, identifies doc pages that need updates, and drafts content that follows the style guide in `fern/pages/CONTRIBUTING.mdx`.

To preview Fern docs locally:

```bash
fern docs dev
```

To run non-interactive validation:

```bash
fern check
```

PRs that touch `fern/**` also get a preview from `.github/workflows/branch-docs.yml` when `FERN_TOKEN` is available to the workflow.

Fern docs publishing is handled by the `publish-fern-docs` job in `.github/workflows/release-tag.yml` when a release tag is created.

`docs/` and `mise run docs` / `mise run docs:serve` are still kept for the legacy Sphinx build during the transition, but they are no longer the primary published docs workflow.

See [fern/pages/CONTRIBUTING.mdx](fern/pages/CONTRIBUTING.mdx) for the current docs authoring guide.

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
