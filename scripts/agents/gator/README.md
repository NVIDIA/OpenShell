# Gator Agent

Launch a headless sandbox agent that runs the `gator-gate` skill against OpenShell issues and pull requests. The default and currently only supported harness is Codex.

## Prerequisites

- `gh` is authenticated on the host and has access to `NVIDIA/OpenShell`.
- For `--harness codex`, `codex login` has created `$HOME/.codex/auth.json`.
- For `--harness codex`, local Codex auth must include an access token, refresh token, and account ID.
- A Docker, Podman, or Kubernetes gateway is available. Local builds require
  Docker or Podman; a prebuilt image does not require a local container engine.

## Usage

```shell
./scripts/agents/run.sh \
  --agent gator \
  --gateway docker-dev \
  --harness codex \
  "Run gator on PR 1536 and keep watching until it closes or merges."
```

By default the launcher uses `scripts/agents/gator/Dockerfile` as the sandbox image source. It builds `scripts/agents/gator/` as the image context, so gator-specific image files such as `policy.yaml` and `bin/gh` stay with the gator agent. The launcher bakes a task-independent prompt template, skills, subagents, and shared runtime files into `/etc/openshell/agent-payload`, then passes the resulting image reference to `openshell sandbox create`.

The PR assignment, operator test authorization, harness selection, watch mode, and polling interval are runtime inputs, not rendered image contents. The launcher supplies the non-secret assignment as `OPENSHELL_AGENT_TASK` in the canonical process command. The supervisor assembles the prompt once in memory and sends it to each harness cycle on stdin; cycles do not read task instructions from an agent-writable file. Assignment text is literal data, so shell syntax and template tokens inside it are not evaluated. Do not put credentials in assignments; use providers. Runtime command metadata can contain the assignment. This separates reusable tooling from per-run instructions; it does not make prompt instructions a security boundary.

Without `--image`, the launcher builds and tags an image for each invocation,
but task-only or supervision-setting changes reuse identical tooling build
inputs. Docker and Podman builds use the gateway's engine; an explicit
`CONTAINER_ENGINE` must match it.

## Kubernetes image delivery

The launcher discovers the compute driver from the selected gateway. It does
not infer a local cluster from a loopback gateway endpoint: that endpoint could
be a port-forward to a remote deployment. Select one of these image paths for
a Kubernetes gateway.

For local k3d, explicitly identify the cluster serving the gateway. The launcher
requires the matching current kube context and a running local cluster, builds
with Docker, and imports the image into that cluster before creating a sandbox:

```shell
OPENSHELL_WORKSPACE=gator mise exec k3d@5.9.0 -- ./scripts/agents/run.sh \
  --agent gator --gateway openshell-dev-main \
  --k3d-cluster openshell-dev-main --name gtr-pr-1234 --watch \
  "Review and monitor PR #1234 through the gator-gate workflow."
```

The cluster selection is an operator assertion that the gateway uses that
cluster; it is not inferred from the gateway name. Its workload image pull
policy must allow imported images (`if_not_present` or `never`). The local
Skaffold configuration uses `if_not_present`.

For a registry-backed deployment, build and publish tooling once without
changing gateway settings, importing providers, reading provider credentials,
or launching a sandbox:

```shell
./scripts/agents/run.sh --agent gator --gateway remote-kube \
  --publish-image registry.example.com/team/gator:payload-13 --build-only
```

The builder uses existing Docker/Podman registry authentication. Both local and
remote Kubernetes nodes must be able to pull from the chosen registry; private
registries require the deployment's image-pull credential configuration. Builds
target the local builder's platform, so build on a matching platform for the
target nodes. Multi-platform builds are not provided by this launcher.

The launcher prints `Tooling image: REGISTRY/REPOSITORY@sha256:DIGEST` after a
successful push. Reuse that full reference for subsequent tasks:

```shell
OPENSHELL_WORKSPACE=gator ./scripts/agents/run.sh \
  --agent gator --gateway remote-kube --name gtr-pr-1234 --watch \
  --image "$GATOR_IMAGE" \
  "Review and monitor PR #1234 through the gator-gate workflow."
```

Set `GATOR_IMAGE` to the printed digest-pinned reference, not a mutable tag.
`--image` skips local builds and cluster imports and works with Docker/Podman
gateways too. It cannot be combined with `--from`, `--codex-bin`,
`--k3d-cluster`, `--publish-image`, or `--build-only`. The image must contain
tooling built by this launcher with the same agent ID and payload version as
the local manifest. Startup validates that contract before running the agent;
legacy images with baked assignments are incompatible. Only reuse trusted
tooling images: the contract check does not authenticate their contents.

Omit `--build-only` from `--publish-image` to build, push, and launch in one
invocation. A failed push, missing repository digest, or failed k3d import
stops the launcher before gateway settings, provider configuration, or sandbox
creation. Kubernetes launches without an explicit image-delivery choice fail
with guidance rather than guessing a cluster or registry.

## Runtime and providers

Use `--harness codex` to select Codex explicitly. Other harness names are rejected until their support is added to `agent.yaml` and `scripts/agents/runtime/harnesses/<name>/`. Agent directories do not carry their own harness implementations; they provide prompt templates and optional skills or subagents for the shared runtime to inject.

Use `--codex-bin "$(command -v codex)"` only when the host executable is compatible with the sandbox OS and architecture.

The manifest-driven launcher at `scripts/agents/run.sh` reads `agent.yaml`, which defines the versioned immutable payload, prompt template, provider profile IDs, provider credential sources, gateway settings, skills, subagents, supporting resources, sandbox defaults, runtime mode, and harness defaults. The shared sandbox entrypoint at `scripts/agents/runtime/entrypoint.sh` starts the in-sandbox supervisor, which invokes the selected harness adapter for bounded cycles.

The launcher:

- Scans `profile_paths` in manifest order and imports or updates `providers/github-gator.yaml`.
- Creates or updates the `github-gator` provider from `gh auth token`.
- Selects the requested harness and bakes the common runtime into the immutable sandbox payload.
- Builds with the latest Codex CLI by default. Docker can reuse the cached install layer; rebuild with that layer's cache disabled to fetch a newer release.
- For `--harness codex`, imports `providers/codex-gator.yaml`, creates or updates the `codex-gator` provider from `$HOME/.codex/auth.json`, and stores the refresh token as gateway-only refresh material.
- For `--harness codex`, configures gateway-managed refresh for `CODEX_AUTH_ACCESS_TOKEN` and rotates it before launching the sandbox.
- Passes the non-secret Codex account ID from host auth as `CODEX_ACCOUNT_ID`. The harness writes it literally into `auth.json` for local workspace discovery; access tokens remain opaque provider placeholders and refresh tokens remain gateway-only.
- Enables `agent_policy_proposals_enabled` and `proposal_approval_mode=auto` at gateway scope.
- Uses the gator image policy copied to `/etc/openshell/policy.yaml`.
- Installs the gator-specific `gh` wrapper from `gator/bin/gh` as `/usr/local/bin/gh` to fail closed when same-head-SHA history cannot be checked, prevent duplicate dispositions, and require versioned review payloads.
- Installs `gator/bin/review-feedback-ledger` as `/usr/local/bin/review-feedback-ledger` so reviews receive tree- and patch-aware scope, prior summaries and findings, resolution state, convergence telemetry, and the three-round Warning budget.
  Patch identity uses fetched merge-base/head trees in a temporary bare Git
  repository, avoiding GitHub's full-diff size limit without checking out PR
  code. If those trees cannot be fetched, the ledger retains feedback and
  exact-SHA history but disables rebase-equivalence shortcuts.
- Installs `gator/bin/resolve-gator-review-threads` so a follow-up commit that
  demonstrably fixes a Gator inline finding can resolve the corresponding
  Gator-owned GitHub review thread without touching human review threads.
- Installs `gator/bin/validate-review-findings` to downgrade blockers that lack the required reachability, ownership, base-vs-head, impact, and reproducer evidence.
- Keeps that normalized evidence as Gator's internal review contract, then renders validated blockers for people as a read-aloud `Summary`, an actionable `Fix`, and a deterministic `Verify`. Exact paths and only the additional provenance an implementation agent needs appear in collapsed `Agent context`; raw evidence headings such as `Base` and `Head` are not posted publicly. Review-process provenance, docs and E2E disposition, SHAs, and state codes appear at the end of the summary in collapsed `Gator metadata`, while required human actions remain visible.
- Bakes `scripts/agents/gator/skills/gator-gate/SKILL.md` into `/etc/openshell/agent-payload`.
- Bakes `.claude/agents/principal-engineer-reviewer.md` so the selected harness can run a deterministic independent reviewer execution through `/etc/openshell/agent-payload/runtime/subagent.sh principal-engineer-reviewer < task.md`.
- For `--harness codex`, optionally bakes a host Codex executable as `/etc/openshell/agent-payload/runtime/harnesses/codex/codex`.
- Starts the selected harness without a TTY.
- Runs gator in `watch` mode by default. The sandbox stays alive while the supervisor sleeps between bounded Codex cycles, so Codex is not connected during passive PR waits. The supervisor prints periodic heartbeat lines during active cycles and passive sleeps.
- Makes each watch cycle compare its immutable payload version with the version published on the default branch. A stale watcher stops without GitHub writes and must be relaunched.
The GitHub provider profile allows read-only GraphQL queries on `api.github.com/graphql` so `gh` read paths can use GraphQL when needed. Its only GraphQL mutation is the named `ResolveGatorReviewThread` operation, restricted to the `resolveReviewThread` root field. All other writes remain REST-only and scoped to the two allowed repositories.

Set `GATOR_CODEX_ACCESS_CREDENTIAL_KEY` or pass `--codex-access-key` if the gator Codex profile uses a credential key other than `CODEX_AUTH_ACCESS_TOKEN` for the short-lived access token.

Use `--once` for a single reconciliation cycle. Use `--poll-interval <seconds>` to change the default 15-minute watch cadence.

The launcher preserves existing gateway-owned Codex refresh material by default so multiple gator sandboxes do not overwrite each other's refresh-token lineage from host Codex auth. If gateway rotation fails, the launcher automatically resets gateway refresh material from host Codex auth and retries once. After `codex logout && codex login`, you can also pass `--reset-refresh` to force that reset before rotation.

## Tests

```shell
bash scripts/agents/gator/bin/gh_guard_test.sh
bash scripts/agents/gator/bin/review_feedback_ledger_test.sh
bash scripts/agents/gator/bin/resolve_gator_review_threads_test.sh
bash scripts/agents/runtime/harnesses/codex/exec_test.sh
bash scripts/agents/run_test.sh
bash scripts/agents/image_test.sh
bash scripts/agents/runtime/launch_test.sh
bash scripts/agents/runtime/supervisor_test.sh
```
