# Gator Agent

Launch a headless sandbox agent that runs the `gator-gate` skill against OpenShell issues and pull requests. The default and currently only supported harness is Codex.

## Prerequisites

- `gh` is authenticated on the host and has access to `NVIDIA/OpenShell` and `NVIDIA/OpenShell-Community`.
- For `--harness codex`, `codex login` has created `$HOME/.codex/auth.json`.
- For `--harness codex`, local Codex auth must include an access token, refresh token, and account ID.
- A local gateway is available when using the default local Dockerfile source.

## Usage

```shell
./scripts/agents/run.sh \
  --agent gator \
  --gateway docker-dev \
  --harness codex \
  "Run gator on PR 1536 and keep watching until it closes or merges."
```

By default the launcher uses `scripts/agents/gator/Dockerfile` as the sandbox source. Local gateways build `scripts/agents/gator/` as the image context, so gator-specific image files such as `policy.yaml` and `bin/gh` stay with the gator agent. The launcher bakes rendered prompts, skills, subagents, and shared runtime files into `/etc/openshell/agent-payload`, so `--from` must point to a local Dockerfile or directory containing a Dockerfile.

Use `--harness codex` to select Codex explicitly. Other harness names are rejected until their support is added to `agent.yaml` and `scripts/agents/runtime/harnesses/<name>/`. Agent directories do not carry their own harness implementations; they provide prompt templates and optional skills or subagents for the shared runtime to inject.

Use `--codex-bin "$(command -v codex)"` only when the host executable is compatible with the sandbox OS and architecture.

The manifest-driven launcher at `scripts/agents/run.sh` reads `agent.yaml`, which defines the agent prompt template, provider profile IDs, provider credential sources, gateway settings, skills, subagents, sandbox defaults, runtime mode, and harness defaults. The shared sandbox entrypoint at `scripts/agents/runtime/entrypoint.sh` starts the in-sandbox supervisor, which invokes the selected harness adapter for bounded cycles.

The launcher:

- Scans `profile_paths` in manifest order and imports `providers/github-gator.yaml`.
- Creates or updates the `github-gator` provider from `gh auth token`.
- Selects the requested harness and bakes the common runtime into the immutable sandbox payload.
- For `--harness codex`, imports `providers/codex-gator.yaml`, creates or updates the `codex-gator` provider from `$HOME/.codex/auth.json`, and stores the refresh token as gateway-only refresh material.
- For `--harness codex`, configures gateway-managed refresh for `CODEX_AUTH_ACCESS_TOKEN` and rotates it before launching the sandbox.
- Enables `providers_v2_enabled` and `agent_policy_proposals_enabled` at gateway scope. Any accepted proposal waits for human review unless the gateway is configured with a managed maximum and the sandbox uses managed `auto` mode.
- Uses the gator image policy copied to `/etc/openshell/policy.yaml`.
- Installs the gator-specific `gh` wrapper from `gator/bin/gh` as `/usr/local/bin/gh` to prevent duplicate same-head-SHA gator dispositions.
- Bakes `scripts/agents/gator/skills/gator-gate/SKILL.md` into `/etc/openshell/agent-payload`.
- Bakes `.claude/agents/principal-engineer-reviewer.md` so the selected harness can run a deterministic independent reviewer execution through `/etc/openshell/agent-payload/runtime/subagent.sh principal-engineer-reviewer < task.md`.
- For `--harness codex`, optionally bakes a host Codex executable as `/etc/openshell/agent-payload/runtime/harnesses/codex/codex`.
- Starts the selected harness without a TTY.
- Runs gator in `watch` mode by default. The sandbox stays alive while the supervisor sleeps between bounded Codex cycles, so Codex is not connected during passive PR waits. The supervisor prints periodic heartbeat lines during active cycles and passive sleeps.
The GitHub provider profile allows read-only GraphQL queries on `api.github.com/graphql` so `gh` read paths can use GraphQL when needed. Write operations remain REST-only and scoped to the two allowed repositories.

Set `GATOR_CODEX_ACCESS_CREDENTIAL_KEY` or pass `--codex-access-key` if the gator Codex profile uses a credential key other than `CODEX_AUTH_ACCESS_TOKEN` for the short-lived access token.

Use `--once` for a single reconciliation cycle. Use `--poll-interval <seconds>` to change the default 15-minute watch cadence.

The launcher preserves existing gateway-owned Codex refresh material by default so multiple gator sandboxes do not overwrite each other's refresh-token lineage from host Codex auth. If gateway rotation fails, the launcher automatically resets gateway refresh material from host Codex auth and retries once. After `codex logout && codex login`, you can also pass `--reset-refresh` to force that reset before rotation.
