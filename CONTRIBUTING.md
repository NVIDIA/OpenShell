# Contributing to OpenShell

OpenShell is built agent-first. We use agents to design and implement systems, while humans manage product decisions and the project roadmap.

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

Issues labeled [`good first issue`](https://github.com/NVIDIA/OpenShell/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) are scoped, well-documented, and friendly to new contributors. Start there. If you need guidance, comment on the issue.

An open issue is not necessarily accepted or ready to be worked on. Human contributors should look for `state:accepted`, roadmap placement, `good first issue`, or `help wanted`, or ask a maintainer before starting. Unattended agents additionally require the appropriate human-applied `agent:*` request label; an agent directly asked to work on a specific issue does not.

## Before You Open an Issue

Search open and closed issues for the same need. Bug reports and feature requests must include:

1. **User Story:** who needs the change and what they need to do.
2. **Problem Statement:** a concise summary of what is broken or missing in the current behavior.
3. **Impact / Why This Matters:** the consequences of the current behavior, the current workaround, and why that workaround is insufficient.
4. **Acceptance Criteria:** specific, observable outcomes that define success.

Feature requests must also propose a user-facing workflow and describe alternatives considered. Define the externally observable behavior and leave internal implementation choices open. Bug reports instead include minimal reproduction steps, the OpenShell version and relevant environment, and a small, redacted log excerpt when it materially clarifies the behavior.

The project includes optional [agent skills](#agent-skills-for-contributors) for self-service troubleshooting and exploration. Use them when they help you, but summarize any useful result in your own words rather than pasting a diagnostic transcript.

### When to Open an Issue

- A workflow behaves differently from what you need or reasonably expect.
- OpenShell does not support an outcome that matters to your workflow.
- The available documentation or configuration does not explain how to complete a supported workflow.
- Security vulnerabilities must follow [SECURITY.md](SECURITY.md) — **not** GitHub issues.

### When NOT to Open an Issue

- General questions or open-ended discussion — use [GitHub Discussions](https://github.com/NVIDIA/OpenShell/discussions).
- Security vulnerabilities — follow [SECURITY.md](SECURITY.md) instead.

## Before You Submit a Change

Do not start substantial issue-backed work until a maintainer has accepted the issue, unless a maintainer directly asks you to investigate or implement it. Once the work is authorized, use your agent to investigate the current code and behavior. If the issue contains earlier diagnostics, verify them rather than relying on them.

Use agents and the repository skills as needed to understand the affected code, evaluate tradeoffs, implement the smallest coherent change, and verify it. The pull request should explain what changed and how it was tested; it should not substitute an agent transcript for the contributor's understanding.

## Agent Skills for Contributors

Skills live in `.agents/skills/`. Your agent's harness can discover and load them natively. Here is the full inventory:

| Category        | Skill                     | Purpose                                                                                             |
| --------------- | ------------------------- | --------------------------------------------------------------------------------------------------- |
| Getting Started | `openshell-cli`           | CLI usage, sandbox lifecycle, provider management, BYOC workflows                                   |
| Getting Started | `debug-openshell-cluster` | Diagnose gateway deployment and health issues                                                       |
| Getting Started | `debug-inference`         | Diagnose `inference.local`, host-backed local inference, and direct external inference setup issues |
| Contributing    | `create-spike`            | Investigate a problem, produce a structured GitHub issue                                            |
| Contributing    | `create-rfc`              | Create RFC proposals from the repository template                                                   |
| Contributing    | `build-from-issue`        | Plan and implement work from a GitHub issue (maintainer workflow)                                   |
| Contributing    | `create-github-issue`     | Create well-structured GitHub issues                                                                |
| Contributing    | `create-github-pr`        | Create pull requests with proper conventions                                                        |
| Reviewing       | `review-github-pr`        | Summarize PR diffs and key design decisions                                                         |
| Reviewing       | `review-security-issue`   | Assess security issues for severity and remediation                                                 |
| Reviewing       | `fix-security-issue`      | Implement an approved security remediation plan                                                     |
| Reviewing       | `watch-github-actions`    | Monitor CI pipeline status and logs                                                                 |
| Reviewing       | `launch-openshell-gator`  | Launch and supervise OpenShell gator agents for issue and PR monitoring                             |
| Reviewing       | `test-release-canary`     | Dispatch and iterate on the Release Canary workflow that smoke-tests published artifacts            |
| Triage          | `triage-issue`            | Assess, classify, and route community-filed issues                                                  |
| Platform        | `generate-sandbox-policy` | Generate YAML sandbox policies from requirements or API docs                                        |
| Platform        | `helm-dev-environment`    | Start and manage the local Kubernetes development environment                                       |
| Platform        | `tui-development`         | Development guide for the ratatui-based terminal UI                                                 |
| Platform        | `build-openshell-mxc-windows` | Maintain and validate the build-only x64 and ARM64 Windows MSVC lane                             |
| Documentation   | `update-docs`             | Scan recent commits and draft doc updates for user-facing changes                                   |
| Maintenance     | `sync-agent-infra`        | Detect and fix drift across agent-first infrastructure files                                        |
| Reference       | `sbom`                    | Generate SBOMs and resolve dependency licenses                                                      |

### Workflow Chains

Skills connect into pipelines. Individual skill files don't describe these relationships.

- **Community inflow:** `triage-issue` → human disposition and roadmap placement → `create-spike` when needed → `build-from-issue`
- **Internal development:** `create-spike` → human disposition and roadmap placement → `build-from-issue`
- **Security:** `review-security-issue` → `fix-security-issue`
- **Policy iteration:** `openshell-cli` → `generate-sandbox-policy`

### Issue Lifecycle, Roadmap, and Agent Work

OpenShell separates technical assessment, roadmap decisions, sequencing, and agent delegation.

An open issue is not automatically accepted or ready for implementation. Check its `state:*` label before starting work, and ask a maintainer when its status is unclear.

#### The Four Decisions

Each issue can require four independent decisions:

| Decision | Question | Recorded by |
|---|---|---|
| Assessment | Is the report technically valid, and is there enough evidence to act on it? | `state:*` |
| Disposition | Should OpenShell pursue the work? | `state:accepted`, roadmap placement, or closure as not planned |
| Sequencing | Where does accepted work sit relative to everything else? | Placement on the [OpenShell Roadmap](https://github.com/orgs/NVIDIA/projects/233) |
| Ownership | Will a human implement the issue, will a user directly instruct an agent, or will a maintainer queue it for an unattended agent? | Direct instruction or optional `agent:*` workflow |

`state:validated` confirms that the factual assessment is complete, but it does not mean the project has accepted the work. A maintainer signals acceptance with `state:accepted` or roadmap placement. Roadmap placement also communicates sequencing, but it does not assign an owner or queue an unattended agent.

#### Who Controls Each Decision

Agents investigate issues, collect evidence, and report technical findings. Humans retain the product and investment decisions.

| Action | Who performs it |
|---|---|
| Assess technical validity and impact | Triage agent or human triager |
| Request missing evidence | Triage agent or human triager |
| Mark the assessment complete with `state:validated` | Triage agent or human triager |
| Accept or decline the work with `state:accepted`, roadmap placement, or closure | Maintainer |
| Place the issue on the roadmap or move it | Maintainer |
| Directly request an agent plan | User |
| Queue an agent plan with `agent:plan-requested` | Maintainer |
| Produce a plan, implement it, and open a pull request | Agent |
| Directly request agent implementation | User |
| Queue approved implementation with `agent:implementation-requested` | Maintainer |

Agents do not apply `state:accepted`, place issues on the roadmap, or apply `agent:plan-requested` or `agent:implementation-requested`.

#### Issue State

The `state:*` namespace records the issue's disposition for all contributors, regardless of who might implement it.

| State | Meaning | Normal next action |
|---|---|---|
| `state:triage-needed` | The issue has not been assessed. New issues from users without repository write access receive this automatically. | Investigate the report and record the result. |
| `state:needs-info` | The assessment needs specific evidence or reproduction details. | The reporter or another contributor supplies the requested information. |
| `state:validated` | The factual assessment is complete. | A maintainer accepts the issue, declines it, or asks for more evidence. |
| `state:accepted` | A maintainer decided that OpenShell should pursue the issue. | A human may implement it, or a maintainer may delegate work to an agent. |

Keep one of these states on an open issue. When new evidence resolves a `state:needs-info` request, reassess the issue and move it to `state:validated` if the evidence is sufficient.

`state:stale` is an inactivity marker, not a lifecycle decision. Accepted issues and issues awaiting human disposition are exempt from stale handling. An issue in `state:needs-info` can become stale if no new evidence arrives.

#### Assessing an Incoming Issue

Triage checks the user story, reproduction or workflow, environment, related issues, current releases, and the relevant code paths. The assessment ends in one of these outcomes:

| Outcome | State or resolution |
|---|---|
| A bug is confirmed. | Replace the intake state with `state:validated`. |
| A feature proposal is technically coherent and feasible. | Replace the intake state with `state:validated`. |
| The report is credible but needs a deeper investigation or spike. | Add the `spike` label when available and use `state:validated` so a human can decide whether to invest in the investigation. |
| Critical evidence is missing, or a faithful attempt cannot reproduce the problem. | Use `state:needs-info` and request the exact evidence needed. |
| A released change already fixes the behavior. | Explain the fix and version. Close the issue only when the causal link is clear; otherwise request a retest. |
| Another issue is the canonical report. | Link the canonical issue and close the duplicate. |
| The behavior is expected or caused by unsupported configuration. | Explain the finding and close the issue with the appropriate GitHub reason. |
| The report describes a security vulnerability. | Stop public triage and follow the private process in `SECURITY.md`. |

Triage establishes facts and impact. It does not decide whether the project should spend time on the work.

#### Human Disposition

When an issue reaches `state:validated`, a maintainer chooses one of three paths:

- **Accept:** apply `state:accepted`, place the issue on the roadmap, or do both. Either action signals that OpenShell should pursue the work; roadmap placement additionally records sequencing.
- **Decline:** close it as not planned and record the rationale.
- **Await more evidence:** replace `state:validated` with `state:needs-info` and leave it off the roadmap.

Do not use `state:accepted` as shorthand for technical validity, roadmap sequencing, or agent authorization. It records the human decision that OpenShell should pursue the work. Roadmap placement records the same acceptance decision plus sequencing.

#### Roadmap

OpenShell does not use priority labels. Sequencing comes from the [OpenShell Roadmap](https://github.com/orgs/NVIDIA/projects/233): a maintainer associates an issue with a roadmap item, signaling acceptance and giving it timing. Issues tracked on the roadmap carry the `roadmap` label.

An issue with `state:accepted` and no roadmap association is real work the project intends to do, but it is not scheduled. Ask a maintainer before starting on one.

Roadmap placement does not assign an owner. A roadmap issue still needs a human contributor, a direct user instruction to an agent, or an unattended-agent queue label.

`good first issue` and `help wanted` describe contributor suitability, not sequencing.

#### Human or Agent Ownership

A human contributor may implement an accepted issue without any `agent:*` label. Before starting, check for an assignee, linked pull request, active branch, or comment that shows someone else is already working on it.

Maintainers use the `agent:*` workflow to queue work for always-on or unattended agents that scan issues. Keep exactly one agent-workflow label on the issue at a time. When a user directly asks an agent to plan or implement a specific issue, that instruction authorizes the requested phase and the corresponding request label is not required.

| Agent workflow | Applied by | Meaning |
|---|---|---|
| `agent:plan-requested` | Maintainer | Ask an agent to produce an implementation plan. |
| `agent:plan-ready` | Agent | The plan is ready for human review. |
| `agent:implementation-requested` | Maintainer | The plan is approved and an agent may implement it. |
| `agent:in-progress` | Agent | Authorized implementation is underway. |
| `agent:pr-opened` | Agent | The implementation produced a pull request. |

The normal delegated workflow is:

```text
(state:accepted OR roadmap placement)
  |
  +-- agent:plan-requested
        |
        +-- agent:plan-ready
              |
              +-- agent:implementation-requested
                    |
                    +-- agent:in-progress
                          |
                          +-- agent:pr-opened
```

`agent:plan-requested` authorizes an unattended agent to pick up planning, not implementation. `agent:implementation-requested` confirms that a human reviewed the plan and authorizes an unattended agent to pick up implementation. Agents never apply either request label. Planning authority does not imply implementation authority.

#### Spikes

Use a spike when the report is credible but technical uncertainty prevents a buildable plan. The triage assessment should identify the unknowns and the evidence the spike needs to produce.

A maintainer first decides whether OpenShell should invest in the investigation. If accepted, the maintainer places it on the roadmap and may request agent work. The spike records its findings in an issue and uses:

- `state:validated` when the evidence supports a human accept or decline decision.
- `state:needs-info` when material evidence or an external decision is still missing.

A completed spike does not automatically authorize implementation. The resulting issue follows the same human disposition process.

#### Security Issues

Do not file or discuss suspected vulnerabilities in a public GitHub issue. Follow the disclosure instructions in `SECURITY.md`.

Maintainers use the specialized security review and remediation workflow for an authorized security issue. For unattended processing, it uses the same queue controls:

1. A maintainer applies `agent:plan-requested` to request a security review and remediation plan.
2. The review agent replaces it with `agent:plan-ready`.
3. A maintainer reviews the plan and applies `agent:implementation-requested`.
4. The remediation agent implements the approved plan.

A user may instead directly request review or remediation from the specialized skill. The direct request replaces the corresponding queue label, but a request for review still does not authorize remediation. General implementation agents do not process issues labeled `topic:security`.

#### When an Issue Is Ready for Work

| You are | Ready when |
|---|---|
| A human contributor | The issue has `state:accepted`, roadmap placement, an invitation to contribute, or maintainer confirmation, and has no conflicting owner or implementation. |
| An unattended agent scanning for planning work | The issue has `state:accepted` or roadmap placement, plus the human-applied `agent:plan-requested` label. |
| An unattended agent scanning for implementation work | The issue has `state:accepted` or roadmap placement, plus an approved plan and the human-applied `agent:implementation-requested` label. |
| An agent directly instructed by a user | The issue has `state:accepted` or roadmap placement, no conflicting owner or implementation, and the instruction explicitly requests the phase the agent will perform. |

Issues with `state:triage-needed`, `state:needs-info`, or `state:validated` are not ready for implementation unless a maintainer has separately placed them on the roadmap. Either `state:accepted` or roadmap placement records the required human acceptance decision.

#### Stale Issues

Inactive issues and pull requests are automatically labeled `state:stale` after 14 days without activity. Automated closing is currently disabled. Comment on the item or remove `state:stale` to keep it active. Issues awaiting triage or human disposition, accepted issues, active agent workflows, and roadmap issues are exempt. `state:needs-info` may become stale when no new evidence arrives.

## Prerequisites

Install [mise](https://mise.jdx.dev/). This is used to set up the development environment.

```bash
# Install mise (macOS/Linux)
curl https://mise.run | sh
```

After installing `mise`, activate it with `mise activate` or [add it to your shell](https://mise.jdx.dev/getting-started.html).

Shell setup examples:

```bash
# Bash
echo 'eval "$(~/.local/bin/mise activate bash)"' >> ~/.bashrc

# Fish
echo '~/.local/bin/mise activate fish | source' >> ~/.config/fish/config.fish

# Zsh
echo 'eval "$(~/.local/bin/mise activate zsh)"' >> ~/.zshrc
```

Project requirements:

- Rust 1.90+
- Python 3.11+
- Docker (running)

### Z3 installation

The `openshell-prover` crate links against Z3. On macOS and Linux, install the
system Z3 development package; `z3-sys` discovers it through `pkg-config`.

```bash
# macOS
brew install z3

# Ubuntu / Debian
sudo apt install libz3-dev

# Fedora
sudo dnf install z3-devel
```

If you prefer not to install Z3 system-wide, use the bundled Z3 feature. This
compiles Z3 from source during the Rust build:

```bash
cargo build -p openshell-prover --features bundled-z3
```

For x86-64 Windows MSVC builds, use one of these Z3 paths:

- System Z3: point `Z3_LIBRARY_PATH_OVERRIDE` at the directory containing the
  64-bit MSVC Z3 library and `Z3_SYS_Z3_HEADER` at the full path to `z3.h`.
  The `windows:*` tasks use this path automatically when `Z3_LIBRARY_PATH_OVERRIDE`
  is set.
- Bundled Z3: pass `--features bundled-z3` so `z3-sys` builds Z3 from source.

Both Windows paths still require `libclang.dll` for `bindgen`. If LLVM is not on
the default search path, set `LIBCLANG_PATH` to the directory containing
`libclang.dll`.

```powershell
$env:LIBCLANG_PATH='C:\Program Files\Microsoft Visual Studio\2022\<Edition>\VC\Tools\Llvm\x64\bin'
cargo build -p openshell-cli --target x86_64-pc-windows-msvc --features bundled-z3
```

To use a local x64 Z3 release with the Windows task wrapper:

```powershell
$env:Z3_LIBRARY_PATH_OVERRIDE='C:\path\to\z3-4.16.0-x64-win\bin'
$env:Z3_SYS_Z3_HEADER='C:\path\to\z3-4.16.0-x64-win\include\z3.h'
mise run --skip-tools windows:build:x64
```

### macOS build tools

Install Apple Command Line Tools before building locally:

```bash
xcode-select --install
```

## Getting Started

```bash
# One-time trust
mise trust

# Run a standalone gateway for local development
mise run gateway
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

### Rust build cache

Mise preserves an existing `SCCACHE_DIR` so each environment can choose where
to store compiler cache entries. When `SCCACHE_DIR` is unset, OpenShell uses
the worktree-local `.cache/sccache` directory. To make cache entries available
to multiple worktrees on a workstation, set the variable to a user-level
directory before activating mise. For example:

```shell
export SCCACHE_DIR="$HOME/.cache/openshell/sccache"
```

CI can select a different directory or configure a remote sccache backend
without changing the workstation setting. Cargo output remains in each
worktree's `target/` directory.

OpenShell does not set `SCCACHE_BASEDIRS`. Sccache loads base directories when
its machine-local daemon starts, but the correct workspace root differs for
each worktree. Cache reuse therefore depends on the compiler inputs: outputs
that embed absolute paths, including Rust dependencies in some builds, can
still miss across worktrees.

## Main Tasks

These are the primary `mise` tasks for day-to-day development:

| Task                 | Purpose                                                 |
| -------------------- | ------------------------------------------------------- |
| `mise run gateway`   | Run a standalone gateway for local development          |
| `mise run sandbox`   | Create or reconnect to the dev sandbox                  |
| `mise run test`      | Default test suite                                      |
| `mise run e2e`       | Default end-to-end test lane                            |
| `mise run ci`        | Full local CI checks (lint, compile/type checks, tests) |
| `mise run docs`      | Validate Fern docs locally                              |
| `mise run helm:docs` | Regenerate the Helm chart README                        |
| `mise run clean`     | Clean build artifacts                                   |

## Project Structure

| Path            | Purpose                                       |
| --------------- | --------------------------------------------- |
| `crates/`       | Rust crates                                   |
| `python/`       | Python SDK and bindings                       |
| `sdk/go/`       | Go SDK (types, gRPC clients, converters)      |
| `sdk/typescript/` | TypeScript SDK (Connect client and generated protobuf bindings) |
| `proto/`        | Protocol buffer definitions                   |
| `tasks/`        | `mise` task definitions and build scripts     |
| `deploy/`       | Dockerfiles, Helm chart, Kubernetes manifests |
| `docs/`         | Published Fern docs source, navigation, and content assets |
| `fern/`         | Fern site config, components, and theme assets |
| `architecture/` | Architecture docs and plans                   |
| `rfc/`          | Request for Comments proposals                |
| `.agents/`      | Agent skills and persona definitions          |

## RFCs

New features always start as GitHub issues using the feature request template. For cross-cutting architectural decisions, API contract changes, or process proposals that need broad consensus, maintainers may ask for an RFC from the issue and assign an RFC number there. RFCs live in `rfc/`. See [rfc/README.md](rfc/README.md) for the full lifecycle and guidelines.

## Documentation

If your change affects user-facing behavior (new flags, changed defaults, new features, bug fixes that contradict existing docs), update the relevant pages under `docs/` in the same PR and adjust `docs/index.yml` if navigation changes. For explicit navigation entries, keep `page:` aligned with `sidebar-title` when present and put relative `slug:` values in `docs/index.yml`. Reserve frontmatter `slug` for folder-discovered pages or absolute URL overrides.

To ensure your doc changes follow NVIDIA documentation style, use the `update-docs` skill.
It scans commits, identifies doc pages that need updates, and drafts content that follows the style guide in `docs/CONTRIBUTING.mdx`.

To preview Fern docs locally:

```bash
mise run docs:serve
```

To run non-interactive validation:

```bash
mise run docs
```

PRs that touch `docs/**` or `fern/**` are validated by `.github/workflows/branch-docs.yml`, and they get a preview when `FERN_TOKEN` is available to the workflow.

Fern docs publishing is handled by the `publish-fern-docs` job in `.github/workflows/release-tag.yml` when a release tag is created.

`docs/` is the source-of-truth docs tree. `fern/` contains the site config, components, and theme assets that publish those pages.

See [docs/CONTRIBUTING.mdx](docs/CONTRIBUTING.mdx) for the current docs authoring guide.

## Pull Requests

1. Create a feature branch from `main`.
2. Make your changes with tests.
3. Run `mise run ci` to verify.
4. Open a PR using the `create-github-pr` skill or manually following the [PR template](.github/PULL_REQUEST_TEMPLATE.md).

PRs for new features, user-visible behavior changes, public API changes, architecture changes, or multi-PR efforts must link an accepted issue. Small documentation fixes, mechanical maintenance, and obvious localized bug fixes may omit a separate issue when the PR contains enough context to review the decision and implementation together.

In the PR's **Related Issue** section, use `Fixes #NNN` or `Closes #NNN` when an issue is required. For an exempt change, write `No issue required:` followed by a brief reason. Security fixes follow the private disclosure process in [SECURITY.md](SECURITY.md).

### Commit Messages

This project uses [Conventional Commits](https://www.conventionalcommits.org/). All commit messages must follow the format:

```text
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

```text
feat(cli): add --verbose flag to openshell run
fix(sandbox): handle timeout errors gracefully
docs: update installation instructions
chore(deps): bump tokio to 1.40
```

### DCO

All human contributions must include a `Signed-off-by` line in each commit message. This certifies you have the right to submit the work under the project license. See the [Developer Certificate of Origin](https://developercertificate.org/). Dependabot-authored dependency update PRs are allowlisted because the bot cannot sign commits.

```bash
git commit -s -m "feat(sandbox): add new capability"
```

DCO sign-off is separate from cryptographic commit signing. CI requires signing for org members so that copy-pr-bot can mirror your PR automatically; see [CI.md](CI.md#commit-signing) for setup.

## CI

How PR CI runs, the `test:e2e`, `test:e2e-gpu`, and `test:e2e-kubernetes` labels, copy-pr-bot, and commit-signing setup are documented in [CI.md](CI.md).
