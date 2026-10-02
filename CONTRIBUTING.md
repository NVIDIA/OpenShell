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

An open issue is not necessarily accepted or ready for implementation. Inspect the repository’s current `state:*` labels and ask a maintainer when its status is unclear. A direct user request authorizes an agent to perform the requested phase without changing the issue’s disposition.

## Before You Open an Issue

Search open and closed issues for the same need. Bug reports and feature requests must include:

1. **User Story:** attest that you personally use OpenShell and describe the specific use case and behavior you directly encountered or need. Agents must ask the human operator for this first-hand context before filing if it is missing.
2. **Problem Statement:** a concise summary of what is broken or missing in the current behavior.
3. **Impact / Why This Matters:** the consequences of the current behavior, the current workaround, and why that workaround is insufficient.
4. **Acceptance Criteria:** specific, observable outcomes that define success.

Feature requests must also propose a user-facing workflow and describe alternatives considered, including relevant OpenShell extension points. When an existing middleware, interceptor, provider, or other extension can satisfy the use case, prefer that path. Running another service alone is not grounds to dismiss it. For changes to configuration, CLI, SDK, or other user experience, include notional examples for human review. Bug reports must include reproduction steps using only an OpenShell deployment, the OpenShell version and relevant environment, and a small, redacted log excerpt when it materially clarifies the behavior. Do not install third-party tools solely to demonstrate reproducibility. Frame every issue entirely in terms of OpenShell.

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
| Platform        | `build-openshell-mxc-windows` | Maintain and validate the x64 and ARM64 Windows MSVC and MXC runtime lane                        |
| Documentation   | `update-docs-from-commits` | Scan recent commits and draft doc updates for user-facing changes                                  |
| Maintenance     | `sync-agent-infra`        | Detect and fix drift across agent-first infrastructure files                                        |
| Reference       | `sbom`                    | Generate SBOMs and resolve dependency licenses                                                      |

### Issue Workflow

Community issues move through triage, technical validation, and human acceptance. The repository's `state:*` labels record these stages. Inspect the current GitHub labels and their descriptions before applying or interpreting them; do not assume a fixed label list. An agent may assess evidence and request missing information. A maintainer decides whether to accept valid work and where it belongs on the roadmap.

A direct request to an agent authorizes the requested planning or implementation. A request to plan alone does not authorize implementation. For unattended work, inspect current state descriptions, maintainer assignments, and comments to determine the authorized phase. Technical validation alone does not authorize implementation. Check for an existing owner, branch, or PR before starting.

Do not file suspected vulnerabilities as public issues. Follow [SECURITY.md](SECURITY.md). Use the specialized security skills for authorized review or remediation.

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

### Z3 installation

The `openshell-prover` crate and standalone `openshell-prover-cli` binary link
directly against Z3. The `openshell-server` crate depends on the prover, and
the `openshell-gateway` binary crate depends on `openshell-server` in turn.
The `openshell-cli` crate does not depend on Z3. The Nix development shell
supplies Z3. For builds outside that shell on macOS and Linux, install the
system Z3 development package; `z3-sys` discovers it through `pkg-config`.
The linker uses the installed static or shared library. The Nix development
shell provides a static Z3 library.

```bash
# macOS
brew install z3

# Ubuntu / Debian
sudo apt install libz3-dev

# Fedora
sudo dnf install z3-devel
```

To build Z3 from source instead, enable `vendored-z3` (requires CMake and a C++
compiler):

```bash
cargo build -p openshell-prover --features vendored-z3
cargo build -p openshell-prover-cli --features vendored-z3
```

Local gateway image and E2E builds enable `vendored-z3` so their
copied gateway binaries do not need a shared Z3 library in the runtime image.

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

`openshell-prover` itself has no `bindgen`/`libclang` dependency, so building
just this crate does not require `LIBCLANG_PATH`:

```powershell
cargo build -p openshell-prover --target x86_64-pc-windows-msvc --features prebuilt-z3
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

1. Create a branch from `main` named `<type>/<issue-id>-<short-description>/<github-username>`, using a Conventional Commits type such as `feat`, `fix`, `docs`, or `chore`.
2. Make your changes with tests.
3. Run the checks appropriate to the affected code and behavior, as described below.
4. Open a PR using the `create-github-pr` skill or manually following the [PR template](.github/PULL_REQUEST_TEMPLATE.md).

Every PR must close an existing issue. In the PR's **Related Issue** section, use `Closes #NNN` for the issue covering that PR's scope. Split multi-PR work into a closable issue for each PR; a tracking issue can link them. Security fixes follow the private disclosure process in [SECURITY.md](SECURITY.md).

### Choose Verification for the Change

Choose checks based on the files changed and the behavior they can affect. Run the relevant formatter, linter, type or compile checks, and tests for those areas. Include dependent components when a shared API, schema, dependency, or build change can affect them.

For contributor guidance, skills, Markdown, and issue or PR templates, validate formatting, links, YAML, and cross references as applicable. Run docs validation when published docs or navigation change. These changes do not require full Rust or SDK suites when they cannot affect those components.

For code changes, run tests for the affected crates or SDKs and their dependent behavior. For sandbox, policy, or deployment infrastructure changes, run the relevant E2E lane. Broaden verification when the change spans components, focused checks fail, or a concrete regression risk remains.

`mise run ci` runs the full repository checks, and `mise run pre-commit` runs broad formatting and lint checks. Use them when that scope is warranted; they are not blanket prerequisites for every change. Report what actually ran and any relevant limitation in the PR. Stop once the checks needed for the change have passed.

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
