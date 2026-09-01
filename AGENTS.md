# Agent Instructions

This file is the primary instruction surface for agents contributing to OpenShell. It is injected into your context on every interaction — keep that in mind when proposing changes to it.

See [CONTRIBUTING.md](CONTRIBUTING.md) for build instructions, task reference, project structure, and the full agent skills table.

## Project Identity

OpenShell is built agent-first. We design systems and use agents to implement them — this is not vibe coding. The product provides safe, sandboxed runtimes for autonomous AI agents, and the project itself is built using the same agent-driven workflows it enables.

## Skills

Agent skills live in `.agents/skills/`. Your harness can discover and load them natively — do not rely on this file for a full inventory. The detailed skills table is in [CONTRIBUTING.md](CONTRIBUTING.md) (for humans).

## Workflow Chains

These pipelines connect skills into end-to-end workflows. Individual skill files don't describe these relationships.

- **Community inflow:** `triage-issue` → human disposition and roadmap placement → `create-spike` when needed → `build-from-issue`
  - Triage establishes facts and marks technically valid issues `state:validated`. A human signals that the project should pursue the work by applying `state:accepted` or placing the issue on the roadmap. The `agent:*` labels support unattended agents that scan for queued work: a human queues a plan with `agent:plan-requested`, the agent returns `agent:plan-ready`, and a human queues implementation with `agent:implementation-requested`. A direct user request to an agent authorizes the requested phase even when the expected lifecycle or workflow labels are missing or incomplete; the agent warns about the discrepancies and continues without changing the labels.
- **Internal development:** `create-spike` → human disposition and roadmap placement → `build-from-issue`
  - Spike explores feasibility and marks its issue `state:validated` when sufficient evidence exists. A human accepts it with `state:accepted` or roadmap placement, or declines it, and optionally queues it through the `agent:*` workflow or directs an agent to it. A direct request proceeds after warning about missing or incomplete expected labels.
- **Security:** `review-security-issue` → `fix-security-issue`
  - General build agents must not process `topic:security` issues. For unattended processing, a human queues specialized review with `agent:plan-requested`; review produces a severity assessment and remediation plan; a human queues remediation with `agent:implementation-requested`. On direct requests to the specialized skills, missing workflow labels produce a warning rather than blocking the requested phase.
- **Policy iteration:** `openshell-cli` → `generate-sandbox-policy`
  - CLI manages the sandbox lifecycle; policy generation authors the YAML constraints.

## Architecture Overview

| Path | Components | Purpose |
|------|-----------|---------|
| `crates/openshell-cli/` | CLI binary | User-facing command-line interface |
| `crates/openshell-conformance/` | CLI conformance library | Reusable driver-agnostic scenarios and command runner |
| `crates/openshell-conformance-cli/` | Conformance CLI | Distributable `list` and `run` entrypoint for gateway conformance |
| `crates/openshell-server/` | Gateway server | Control-plane API, sandbox lifecycle, auth boundary |
| `crates/openshell-sandbox/` | Sandbox runtime | Container supervision, policy-enforced egress routing |
| `crates/openshell-policy/` | Policy engine | Filesystem, network, process, and inference constraints |
| `crates/openshell-router/` | Privacy router | Privacy-aware LLM routing |
| `crates/openshell-bootstrap/` | Gateway metadata | Gateway registration metadata, auth token storage, mTLS bundle storage |
| `crates/openshell-gateway-interceptors/` | Gateway interceptors | Intercepts and transforms configured gRPC requests at the gateway routing boundary |
| `crates/openshell-ocsf/` | OCSF logging | OCSF v1.8.0 event types, builders, shorthand/JSONL formatters, tracing layers |
| `crates/openshell-otel/` | OpenTelemetry support | Shared OTLP trace provider, resource, and tracing-layer construction |
| `crates/openshell-otel-test-support/` | OpenTelemetry test support | Shared loopback OTLP collector fixture for tracing tests |
| `crates/openshell-core/` | Shared core | Common types, configuration, error handling |
| `crates/openshell-extension-core/` | Extension core | Shared extension identity, JWT claims, bearer-token rotation, and TLS transport primitives |
| `crates/openshell-sdk/` | Shared client SDK | Async Rust gateway client (gRPC transport, TLS, OIDC refresh, edge tunnel); consumed by CLI, TUI, and `@openshell/sdk` |
| `crates/openshell-providers/` | Provider management | Credential provider backends |
| `crates/openshell-tui/` | Terminal UI | Ratatui-based dashboard for monitoring |
| `crates/openshell-driver-kubernetes-secrets/` | Kubernetes Secrets credential driver | In-process `CredentialDriver` backend for OpenShell-managed K8s Secret storage |
| `crates/openshell-driver-vault/` | Vault credential driver | In-process `CredentialDriver` backend for Vault-compatible KV storage |
| `crates/openshell-driver-db-credstore/` | Database credential driver | In-process `CredentialDriver` backend for gateway database credential storage |
| `crates/openshell-driver-kubernetes/` | Kubernetes compute driver | In-process `ComputeDriver` backend for K8s sandbox pods |
| `crates/openshell-driver-docker/` | Docker compute driver | In-process `ComputeDriver` backend for local Docker sandbox containers |
| `crates/openshell-driver-podman/` | Podman compute driver | In-process `ComputeDriver` backend for local Podman sandbox containers |
| `crates/openshell-driver-vm/` | VM compute driver | Standalone libkrun-backed `ComputeDriver` subprocess (embeds its own rootfs + runtime) |
| `crates/openshell-prover/` | Policy prover | Policy verification and proof generation |
| `crates/openshell-server-macros/` | Server macros | Compile-time helpers for gateway RPC authorization |
| `crates/openshell-supervisor-middleware/` | Middleware runtime | Generic middleware registry, remote service integration, and chain execution |
| `crates/openshell-supervisor-middleware-builtins/` | Built-in middleware | First-party in-process middleware implementations |
| `crates/openshell-supervisor-network/` | Network supervisor | Proxying, L7 enforcement, policy evaluation, and inference routing |
| `crates/openshell-supervisor-process/` | Process supervisor | Process lifecycle, namespace, and bypass monitoring |
| `crates/openshell-vfio/` | VFIO support | PCI and GPU passthrough preparation and lifecycle |
| `python/openshell/` | Python SDK | Python bindings and CLI packaging |
| `sdk/typescript/` | TypeScript SDK | Native Connect client, curated sandbox API, and generated protobuf types |
| `proto/` | Protobuf definitions | gRPC service contracts |
| `deploy/` | Docker, Helm, K8s | Dockerfiles, Helm chart, manifests |
| `docs/` | Published docs | MDX pages, navigation, and content assets |
| `fern/` | Docs site config | Fern site config, components, and theme assets |
| `.agents/skills/` | Agent skills | Workflow automation for development |
| `.agents/agents/` | Agent personas | Sub-agent definitions (e.g., reviewer, doc writer) |
| `architecture/` | Architecture docs | Design decisions and component documentation |

## Vouch System

- First-time external contributors must be vouched before their PRs are accepted. The `vouch-check` workflow auto-closes PRs from unvouched users.
- Org members and collaborators bypass the vouch gate automatically.
- Maintainers vouch users by commenting `/vouch` on a Vouch Request discussion. The `vouch-command` workflow appends the username to `.github/VOUCHED.td`.
- Skills that create PRs (`create-github-pr`, `build-from-issue`) should note this requirement when operating on behalf of external contributors.

## Issue and PR Conventions

- **Bug reports and feature requests** must include a User Story, Problem Statement, Impact / Why This Matters, and Acceptance Criteria. The impact should explain the consequences of the current behavior, the current workaround, and why that workaround is insufficient. Bug reports additionally require reproduction steps and environment details and may include concise, redacted logs.
- **Feature requests** must also include a Proposed Design and Alternatives Considered. The design should define the user-facing workflow and externally observable behavior while leaving internal implementation choices open. Agent investigation is optional.
- **New features** must start as GitHub issues using the feature request template. Open an RFC only after an issue exists; maintainers decide when one is needed and assign RFC numbers from the issue.
- **Issue triage** establishes technical validity and impact evidence. Agents never decide acceptance, apply `state:accepted`, place issues on the roadmap, or apply `agent:plan-requested` or `agent:implementation-requested`. Humans accept or decline validated work; `state:accepted` or roadmap placement records acceptance, and roadmap association additionally carries sequencing. Lifecycle and request labels gate unattended queue pickup. An explicit user instruction authorizes an agent to plan or implement the specified issue even when expected labels are missing or incomplete; the agent warns the user and continues without changing those labels. OpenShell has no `priority:*` labels.
- **PRs** must follow the PR template structure: Summary, Related Issue, Changes, Testing, Checklist. Contributors should use their agent to investigate the current code and behavior for accepted issue-backed work, verify any diagnostics already on the issue, understand the change they submit, and report the resulting implementation and verification—not paste an earlier issue-filing diagnostic.
- **PRs for features, user-visible behavior, public APIs, architecture, or multi-PR efforts** must link an accepted issue. Small docs fixes, mechanical maintenance, and obvious localized bug fixes may state why no issue is required.
- **PRs from unvouched external contributors** are automatically closed. See the Vouch System section above.
- **Security vulnerabilities** must NOT be filed as GitHub issues. Follow [SECURITY.md](SECURITY.md).
- Skills that create issues or PRs (`create-github-issue`, `create-github-pr`, `build-from-issue`) should produce output conforming to these templates.

## Plans

- Store plan documents in `architecture/plans`. This is git ignored so its for easier access for humans. When asked to create Spikes or issues, you can skip to GitHub issues. Only use the plans dir when you aren't writing data somewhere else specific.
- When asked to write a plan, write it there without asking for the location.

## Sandbox Logging (OCSF)

When adding or modifying log emissions in `openshell-sandbox`, determine whether the event should use OCSF structured logging or plain `tracing`.

### When to use OCSF

Use an OCSF builder + `ocsf_emit!()` for events that represent **observable sandbox behavior** visible to operators, security teams, or agents monitoring the sandbox:

- Network decisions (allow, deny, bypass detection)
- HTTP/L7 enforcement decisions
- SSH authentication (accepted, denied, nonce replay)
- Process lifecycle (start, exit, timeout, signal failure)
- Security findings (unsafe policy, unavailable controls, replay attacks)
- Configuration changes (policy load/reload, TLS setup, inference routes, settings)
- Application lifecycle (supervisor start, SSH server ready)

### When to use plain tracing

Use `info!()`, `debug!()`, `warn!()` for **internal operational plumbing** that doesn't represent a security decision or observable state change:

- gRPC connection attempts and retries
- "About to do X" events where the result is logged separately
- Internal SSH channel state (unknown channel, PTY resize)
- Zombie process reaping, denial flush telemetry
- DEBUG/TRACE level diagnostics

### Choosing the OCSF event class

| Event type | Builder | When to use |
|---|---|---|
| TCP connections, proxy tunnels, bypass | `NetworkActivityBuilder` | L4 network decisions, proxy operational events |
| HTTP requests, L7 enforcement | `HttpActivityBuilder` | Per-request method/path decisions |
| SSH sessions | `SshActivityBuilder` | Authentication, channel operations |
| Process start/stop | `ProcessActivityBuilder` | Entrypoint lifecycle, signal failures |
| Security alerts | `DetectionFindingBuilder` | Nonce replay, bypass detection, unsafe policy. Dual-emit with the domain event. |
| Policy/config changes | `ConfigStateChangeBuilder` | Policy load, Landlock apply, TLS setup, inference routes, settings |
| Supervisor lifecycle | `AppLifecycleBuilder` | Sandbox start, SSH server ready/failed |

### Severity guidelines

| Severity | When |
|---|---|
| `Informational` | Allowed connections, successful operations, config loaded |
| `Low` | DNS failures, non-fatal operational warnings, LOG rule failures |
| `Medium` | Denied connections, policy violations, deprecated config |
| `High` | Security findings (nonce replay, Landlock unavailable) |
| `Critical` | Process timeout kills |

### Example: adding a new network event

```rust
use openshell_ocsf::{
    ocsf_emit, NetworkActivityBuilder, ActivityId, ActionId,
    DispositionId, Endpoint, Process, SeverityId, StatusId,
};

let event = NetworkActivityBuilder::new(crate::ocsf_ctx())
    .activity(ActivityId::Open)
    .action(ActionId::Denied)
    .disposition(DispositionId::Blocked)
    .severity(SeverityId::Medium)
    .status(StatusId::Failure)
    .dst_endpoint(Endpoint::from_domain(&host, port))
    .actor_process(Process::new(&binary, pid))
    .firewall_rule(&policy_name, &engine_type)
    .message(format!("CONNECT denied {host}:{port}"))
    .build();
ocsf_emit!(event);
```

### Key points

- `crate::ocsf_ctx()` returns the process-wide `SandboxContext`. It is always available (falls back to defaults in tests).
- `ocsf_emit!()` is non-blocking and cannot panic. It stores the event in a thread-local and emits via `tracing::info!()`.
- The shorthand layer and JSONL layer extract the event from the thread-local. The shorthand format is derived automatically from the builder fields.
- For security findings, **dual-emit**: one domain event (e.g., `SshActivityBuilder`) AND one `DetectionFindingBuilder` for the same incident.
- Never log secrets, credentials, or query parameters in OCSF messages. The OCSF JSONL file may be shipped to external systems.
- The `message` field should be a concise, grep-friendly summary. Details go in builder fields (dst_endpoint, firewall_rule, etc.).

## Sandbox Infra Changes

- If you change sandbox infrastructure, ensure the relevant sandbox e2e path succeeds.

## Network Sockets

- On latency-sensitive TCP streams, disable Nagle's algorithm so small
  request/response frames don't stall on delayed ACKs. Use
  `openshell_core::net::set_tcp_nodelay_best_effort` on an accepted or
  already-connected stream, or `openshell_core::net::connect_tcp_nodelay_best_effort`
  when dialing.
- This applies to loopback/localhost TCP too — the delayed-ACK stall is a timer
  behavior, not wire latency.
- You should skip it for unix domain sockets (no Nagle). It's not critical for
  test-only connections, though using it on any non-UDS TCP stream — tests
  included — is fine and preferred.

## Commits

- Always use [Conventional Commits](https://www.conventionalcommits.org/) format for commit messages
- Format: `<type>(<scope>): <description>` (scope is optional)
- Common types: `feat`, `fix`, `docs`, `chore`, `refactor`, `test`, `ci`, `perf`
- Sign off on each commit for DCO compliance. Use the `--signoff` option to `git commit` to add the `Signed-off-by` footer to ensure the user's configured email address is used.
- Never mention Claude or any AI agent in commits (no author attribution, no Co-Authored-By, no references in commit messages)

## Pre-commit

- Run `mise run pre-commit` before committing.
- Install the git hook when working locally: `mise generate git-pre-commit --write --task=pre-commit`

## Testing

- `mise run pre-commit` — Lint, format, license headers. Run before every commit.
- `mise run test` — Unit test suite. Run after code changes.
- `mise run e2e` — End-to-end tests against a running gateway. Run for infrastructure, sandbox, or policy changes.
- `mise run ci` — Full local CI (lint + compile/type checks + tests). Run before opening a PR.

## Go SDK (`sdk/go/`)

- The Go SDK lives in `sdk/go/` with module path `github.com/NVIDIA/OpenShell/sdk/go`.
- Run `mise run go:ci` for the full SDK CI pipeline (lint, build, test, proto-check, docs-check).
- Proto bindings are generated with `mise run go:proto:gen` from the `.proto` files in `proto/`.
- Domain types in `sdk/go/openshell/v1/types/` must not import proto packages.
- Converters in `sdk/go/openshell/v1/internal/converter/` deep-copy slices and maps at boundaries.
- Tests use bufconn for in-process gRPC and testify for assertions.

## TypeScript SDK (`sdk/typescript/`)

- Run `mise run sdk:ts:ci` for codegen, proto lint, Biome lint, type checking, unit tests, coverage, and build validation.
- Proto bindings are generated with `mise run sdk:ts:proto` from the files selected in `sdk/typescript/buf.gen.yaml`.
- Generated files under `sdk/typescript/src/gen/` are build outputs and must not be committed.
- Keep the curated API free of generated wire types; expose full generated messages and RPCs through `@nvidia/openshell-sdk/raw`.
- The release workflow publishes the package to GitHub Packages. Branch checks exercise the publish path with `npm publish --dry-run`.

## Python

- Always use `uv` for Python commands (e.g., `uv pip install`, `uv run`, `uv venv`)

## Docker

- Always prefer `mise` commands over direct docker builds (e.g., `mise run docker:build` instead of `docker build`)

## Cluster Infrastructure Changes

- If you change gateway deployment infrastructure (e.g., Helm values/templates, gateway image packaging, or deploy logic in `openshell-cli`), update the `debug-openshell-cluster` skill in `.agents/skills/debug-openshell-cluster/SKILL.md` to reflect those changes.

## Skill Maintenance

When behavior, commands, or development workflows change, review the related agent skills in the same branch. Use the `sync-agent-infra` skill for the maintenance map and consistency checks.

## Documentation

- When making changes, update the relevant documentation in the `architecture/` directory.
- When changes affect user-facing behavior, update the relevant published docs pages under `docs/` and navigation in `docs/index.yml`.
- When changing gateway TOML fields, driver-specific config options, config defaults, or Helm rendering of `gateway.toml`, update `docs/reference/gateway-config.mdx` in the same branch.
- `fern/` contains the Fern site config, components, preview workflow inputs, and publish settings.
- Follow the docs style guide in [docs/CONTRIBUTING.mdx](docs/CONTRIBUTING.mdx): active voice, minimal formatting, no filler introductions, `shell` fences for copyable commands, and no duplicate body H1.
- Fern PR previews run through `.github/workflows/branch-docs.yml`, and production publish runs through the `publish-fern-docs` job in `.github/workflows/release-tag.yml` for stable release tags.
- Use the `update-docs` skill to scan recent commits and draft doc updates.

### Architecture Docs

- Architecture docs are short canonical subsystem overviews, not exhaustive implementation notes.
- Update one of the existing top-level architecture docs before adding a new file.
- Put useful crate-specific details in the relevant crate `README.md`.
- Add a new top-level architecture doc only when explicitly requested or when an RFC-level design needs a stable home.
- Keep architecture docs focused on stable boundaries, data/control flow, invariants, and operational constraints.
- Remove stale detail instead of preserving it by default.
- Do not include testing transcripts, historical debugging notes, long source-file inventories, or field-by-field schema references.
- Put user-facing instructions in `docs/`, broad design proposals in `rfc/`, and temporary plans in ignored `architecture/plans/`.

## Security

- Never commit secrets, API keys, or credentials. If a file looks like it contains secrets (`.env`, `credentials.json`, etc.), do not stage it.
- Do not run destructive operations (force push, hard reset, database drops) without explicit human confirmation.
- Scope changes to the issue at hand. Do not make unrelated changes in the same branch.
