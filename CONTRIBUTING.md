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
- **Don't** use agents as a substitute for understanding the system. Read the RFCs, crate READMEs, and published docs.

## First-Time Contributors

We use a vouch system. This exists because AI makes it trivial to generate plausible-looking but low-quality contributions, and we can no longer trust by default.

1. Open a [Vouch Request](https://github.com/NVIDIA/OpenShell/discussions/new?category=vouch-request) discussion.
2. Describe what you want to change and why.
3. Write in your own words. AI-generated vouch requests will be denied.
4. A maintainer will comment `/vouch` if approved, and the request discussion
   will close automatically.
5. Once vouched, you can submit pull requests.

**If you are not vouched, any pull request you open will be automatically closed.** Org members and collaborators with push access bypass this check.

### Finding Work

Issues labeled [`good first issue`](https://github.com/NVIDIA/OpenShell/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) are scoped, well-documented, and friendly to new contributors. Start there. If you need guidance, comment on the issue.

An open issue is not necessarily accepted or ready to be worked on. Human contributors should look for `state:accepted`, roadmap placement, `good first issue`, or `help wanted`, or ask a maintainer before starting. Unattended agents require acceptance or roadmap placement, an active pickup state, the human-applied `needs:*` label for the requested phase, and any required approved plan. An agent directly asked to work on a specific issue warns about missing or incomplete queue labels and continues with the requested phase without changing them.

## Before You Open an Issue

Search open and closed issues for the same need. Bug reports and feature requests must include:

1. **User Story:** who needs the change and what they need to do.
2. **Problem Statement:** a concise summary of what is broken or missing in the current behavior.
3. **Impact / Why This Matters:** the consequences of the current behavior, the current workaround, and why that workaround is insufficient.
4. **Acceptance Criteria:** specific, observable outcomes that define success.

Feature requests must also propose a user-facing workflow and describe alternatives considered. Define the externally observable behavior and leave internal implementation choices open. Bug reports instead include minimal reproduction steps, the OpenShell version and relevant environment, and a small, redacted log excerpt when it materially clarifies the behavior.

The project includes optional [agent skills](#agent-skills) for using OpenShell and contributing to the repository. Use them when they help you, but summarize any useful result in your own words rather than pasting a diagnostic transcript.

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

## Agent Skills

OpenShell keeps skills for using the product separate from skills for developing the repository.

### Skills for Using OpenShell

Public skills live in `skills/` and work without an OpenShell source checkout. Install them with `npx skills add NVIDIA/OpenShell`.

| Skill | Purpose |
| --- | --- |
| `openshell-cli` | CLI usage, sandbox lifecycle, provider management, and BYOC workflows |
| `debug-openshell-cluster` | Diagnose gateway deployment and health issues |
| `debug-inference` | Diagnose attached-provider inference, native endpoints, and migration from the retired managed endpoint |
| `generate-sandbox-policy` | Generate YAML sandbox policies from requirements or API documentation |

Public skills use `openshell --help` for installed command syntax and published OpenShell documentation for product concepts and configuration. They must not depend on repository-relative source or documentation files.

### Agent Skills for Contributors

Contributor and maintainer skills live in `.agents/skills/`. They are marked internal so the Agent Skills CLI excludes them from ordinary public discovery, but repository-aware agent harnesses can discover and load them natively. Internal metadata is a discovery filter, not an access-control boundary.

| Category        | Skill                     | Purpose                                                                                             |
| --------------- | ------------------------- | --------------------------------------------------------------------------------------------------- |
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
| Platform        | `helm-dev-environment`    | Start and manage the local Kubernetes development environment                                       |
| Platform        | `tui-development`         | Development guide for the ratatui-based terminal UI                                                 |
| Platform        | `build-openshell-mxc-windows` | Maintain and validate the build-only x64 and ARM64 Windows MSVC lane                             |
| Documentation   | `update-docs-from-commits` | Scan recent commits and draft doc updates for user-facing changes                                  |
| Maintenance     | `sync-agent-infra`        | Detect and fix drift across agent-first infrastructure files                                        |
| Reference       | `sbom`                    | Generate SBOMs and resolve dependency licenses                                                      |

### Workflow Chains

Skills connect into pipelines. Individual skill files don't describe these relationships.

- **Community inflow:** `triage-issue` → human disposition and roadmap placement → `create-spike` when needed → `build-from-issue`
- **Internal development:** `create-spike` → human disposition and roadmap placement → `build-from-issue`
- **Security:** `review-security-issue` → `fix-security-issue`
- **Policy iteration:** `openshell-cli` → `generate-sandbox-policy`

### Issue Lifecycle, Roadmap, and Agent Work

OpenShell uses three label axes on issues. The [issue workflow guide](docs/contributing/issue-workflow.mdx) defines every value and example. GitHub's issue type, closure reason, assignee, and roadmap placement remain separate metadata.

| Axis | Question | Cardinality on an open issue after intake |
| --- | --- | --- |
| `type:*` | What kind of issue is this? | At most one; it may be absent while intake gathers evidence. |
| `state:*` | Where does the issue stand? | Exactly one. |
| `needs:*` | What work or information is needed next? | At most one; it may be absent during a disposition decision. |

`state:new` means screening or information gathering is pending. `state:validated` means the factual assessment is complete and a human should make a disposition decision promptly. `state:accepted` records a maintainer decision to pursue the work. `state:in-progress` and `state:in-review` describe active work and review. Closed issues use GitHub's closure reason; this rollout leaves already closed items untouched. The separate `status:stale` marker records inactivity without creating a second `state:*` label.

#### Intake and Human Disposition

New community issues receive `state:new`. For this rollout, a human invokes `triage-issue`; the agent checks completeness, duplicates, prior declines, releases, and technical validity, then posts a private summary to `#openshell-triage` mentioning `@openshell-duty-eng`. The duty engineer can invite others into the Slack discussion and directs every public reply, label change, acceptance, or decline. Triage is not automatically invoked on issue creation yet.

Maintainer-authored issues bypass screening and enter `state:accepted` for scheduling and assignment. The automatic-triage follow-on will reconsider this exception. Suspected vulnerabilities follow [SECURITY.md](SECURITY.md) and are never filed as public GitHub issues.

An issue needing specific evidence uses `needs:info` until the reporter or another person responds. A valid issue awaiting disposition uses `state:validated` only for the time needed to make that decision. A maintainer accepts by applying `state:accepted` or placing the issue on the [OpenShell Roadmap](https://github.com/orgs/NVIDIA/projects/233); roadmap placement additionally records sequencing. A maintainer declines by closing with an explanation. Agents never make those investment decisions or add `state:accepted` or roadmap placement.

#### Human and Agent Work

Human contributors may work on accepted issues without agent queue labels. Check for an assignee, branch, linked PR, or discussion that shows someone else is already working on the issue. `good first issue` and `help wanted` describe contributor suitability. OpenShell does not use priority labels.

An unattended agent checks the full label combination before a phase:

| Phase | Required issue state |
| --- | --- |
| Intake screening | `state:new`; this never authorizes planning or implementation. |
| Planning | Acceptance or roadmap placement, `state:accepted` or `state:in-progress`, and human-applied `needs:plan`. |
| Plan review | `state:in-review`, `needs:plan`. |
| Implementation | Acceptance or roadmap placement, `state:accepted` or `state:in-progress`, an approved plan, and human-applied `needs:pr`. |
| PR review | `state:in-review`, `needs:pr`. |

A plan request authorizes planning only. After reviewing the plan, a human changes `needs:plan` to `needs:pr` and returns the issue to `state:accepted` or `state:in-progress` to queue implementation. Agents may move an authorized issue into `state:in-progress` and return it to `state:in-review` when the plan or PR is ready. Agents never apply `needs:plan` or `needs:pr` to queue themselves. `needs:spike` requires a human-approved bounded investigation; `needs:rfc` requires maintainer direction and an assigned RFC number.

An explicit user request for a particular issue authorizes the stated phase even when expected queue labels are missing or incomplete. The agent warns about the discrepancy and continues without changing authorization labels. A direct planning request does not authorize implementation. General build agents do not process `topic:security` issues; the specialized security review and fix skills retain their own human approval and prior-review gates.

#### Pull Requests and Staleness

Issue workflow labels stay on the issue linked from a PR. PR review and merge status are already visible in GitHub; a PR need not duplicate the issue's four axes. A PR without a linked issue may use useful workflow labels but is not assumed to represent accepted work. Feature and multi-PR efforts link accepted issues.

Inactive issues and pull requests receive `status:stale` after 14 days. Automatic closure remains disabled. Comment or remove the marker to keep an item active. Issues awaiting triage or human disposition, accepted issues, active agent work, and roadmap issues are exempt; `needs:info` issues may become stale when no answer arrives.

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

- Rust 1.94+
- Python 3.11+
- Docker (running)
- CMake 3.16+ (only required when building with the `bundled-z3` feature)

### Z3 installation

The `openshell-prover` crate and standalone `openshell-prover-cli` binary link
directly against Z3. The `openshell-server` crate depends on the prover, and
the `openshell-gateway` binary crate depends on `openshell-server` in turn.
These packages forward a `bundled-z3` feature to
`openshell-prover/bundled-z3`. The `openshell-cli` crate does not depend on Z3.
On macOS and Linux, install the system Z3 development package; `z3-sys`
discovers it through `pkg-config`.

```bash
# macOS
brew install z3

# Ubuntu / Debian
sudo apt install libz3-dev

# Fedora
sudo dnf install z3-devel
```

If you prefer not to install Z3 system-wide, use the bundled Z3 feature. This
compiles Z3 from source during the Rust build and requires CMake 3.16+:

```bash
cargo build -p openshell-prover --features bundled-z3
cargo build -p openshell-prover-cli --features bundled-z3
```

For x86-64 and ARM64 Windows MSVC builds, use one of these Z3 paths:

- Prebuilt Z3 (the default for `windows:*` tasks): `z3-sys` downloads the
  pinned Z3 5.1.0 GitHub release for the target architecture on the first
  build. Cargo reuses the extracted archive from its target directory. Windows
  CI authenticates the GitHub API request with `READ_ONLY_GITHUB_TOKEN` and
  preserves the archive in the architecture-specific Cargo target cache. For
  cold local builds, you may set `READ_ONLY_GITHUB_TOKEN` to avoid anonymous
  GitHub API rate limits.
- System Z3: point `Z3_LIBRARY_PATH_OVERRIDE` at the directory containing the
  target-compatible MSVC Z3 library and `Z3_SYS_Z3_HEADER` at the full path to `z3.h`.
  The `windows:*` tasks use this path automatically when `Z3_LIBRARY_PATH_OVERRIDE`
  is set.
- Bundled Z3: for direct Cargo builds, pass `--features bundled-z3` so `z3-sys`
  builds Z3 from source.

`openshell-prover` itself has no `bindgen`/`libclang` dependency, so building
just this crate does not require `LIBCLANG_PATH`:

```powershell
cargo build -p openshell-prover --target x86_64-pc-windows-msvc --features bundled-z3
```

### Windows full build

To build the full set of Windows binaries, including `openshell-gateway.exe`
and `openshell.exe`, use the `windows:build:x64` mise task instead of a
single-crate `cargo build`. It downloads the pinned prebuilt Z3 release by default. A
full build also compiles crates that use `bindgen` (e.g. the MXC driver on
Windows), so it requires `libclang.dll`; if LLVM is not on the default search
path, set `LIBCLANG_PATH` to the directory containing `libclang.dll`:

```powershell
$env:LIBCLANG_PATH='C:\Program Files\Microsoft Visual Studio\2022\<Edition>\VC\Tools\Llvm\x64\bin'
mise run --skip-tools windows:build:x64
```

To use a local x64 Z3 release instead of the prebuilt download, set
`Z3_LIBRARY_PATH_OVERRIDE` and `Z3_SYS_Z3_HEADER` before running the task:

```powershell
$env:Z3_LIBRARY_PATH_OVERRIDE='C:\path\to\z3-5.1.0-x64-win\bin'
$env:Z3_SYS_Z3_HEADER='C:\path\to\z3-5.1.0-x64-win\include\z3.h'
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
| `crates/openshell-policy-schema/` | Canonical authored policy DTOs and bounded YAML/JSON parser |
| `crates/openshell-prover-cli/` | Standalone local policy boundary checker |
| `python/`       | Python SDK and bindings                       |
| `sdk/go/`       | Go SDK (types, gRPC clients, converters)      |
| `sdk/typescript/` | TypeScript SDK (Connect client and generated protobuf bindings) |
| `proto/`        | Protocol buffer definitions and [public API conventions](proto/README.md) |
| `tasks/`        | `mise` task definitions and build scripts     |
| `deploy/`       | Dockerfiles, Helm chart, Kubernetes manifests |
| `docs/`         | Published Fern docs source, navigation, and content assets |
| `fern/`         | Fern site config, components, and theme assets |
| `plans/`        | Local plans (git-ignored)                     |
| `rfc/`          | Request for Comments proposals                |
| `skills/`       | Public skills for using and operating OpenShell |
| `.agents/`      | Contributor skills and persona definitions    |

## RFCs

New features always start as GitHub issues using the feature request template. For cross-cutting architectural decisions, API contract changes, or process proposals that need broad consensus, maintainers may ask for an RFC from the issue and assign an RFC number there. RFCs live in `rfc/`. See [rfc/README.md](rfc/README.md) for the full lifecycle and guidelines.

## Public API conventions

Follow [the protobuf API conventions](proto/README.md) when adding or changing
gRPC contracts. The guide defines entity-reference naming, workspace selectors,
field design, and schema-evolution rules.

## Documentation

If your change affects user-facing behavior (new flags, changed defaults, new features, bug fixes that contradict existing docs), update the relevant pages under `docs/` in the same PR and adjust `docs/index.yml` if navigation changes. For explicit navigation entries, keep `page:` aligned with `sidebar-title` when present and put relative `slug:` values in `docs/index.yml`. Reserve frontmatter `slug` for folder-discovered pages or absolute URL overrides. Keep every page URL equal to its file path under `docs/`; `mise run docs` checks this with `docs:nav`.

To ensure your doc changes follow NVIDIA documentation style, use the `update-docs-from-commits` skill.
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

Release Dev publishes the `dev` docs version from `main`. Release Tag publishes an immutable stable version and updates `latest`. See [fern/README.md](fern/README.md) for the source layout, version model, and publishing workflows.

`docs/` is the source-of-truth docs tree. `fern/` contains the site configuration, components, theme assets, and its README.

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

All human contributions must include a `Signed-off-by` line in each commit message. This certifies you have the right to submit the work under the project license. Dependabot-authored dependency update PRs are allowlisted because the bot cannot sign commits.

The project uses version 1.1 of the [Developer Certificate of Origin](https://developercertificate.org/):

```text
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

```bash
git commit -s -m "feat(sandbox): add new capability"
```

DCO sign-off is separate from cryptographic commit signing. CI requires signing for org members so that copy-pr-bot can mirror your PR automatically; see [CI.md](CI.md#commit-signing) for setup.

## CI

How PR CI runs, the `test:e2e`, `test:e2e-gpu`, and `test:e2e-kubernetes` labels, copy-pr-bot, and commit-signing setup are documented in [CI.md](CI.md).
