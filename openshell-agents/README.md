# OpenShell Agents

`openshell-agents/` contains repository-owned agent launchers. An agent is a
manifest plus prompt assets that the shared launcher turns into an OpenShell
sandbox run. Agents do not own harness implementations. Harness-specific setup
and execution live in `runtime/harnesses/<name>/`.

## Directory Layout

```text
openshell-agents/
  run.sh                    # Generic manifest-driven launcher
  runtime/                  # Shared in-sandbox runtime
    entrypoint.sh           # Starts the in-sandbox supervisor
    supervisor.sh           # Runs bounded harness cycles in once/watch mode
    subagent.sh             # Generic subagent dispatcher
    harnesses/
      codex/                # Codex install and execution adapter
  <agent>/
    agent.yaml              # Agent manifest
    prompts/                # Prompt templates rendered at launch
    providers/              # Provider profile YAML files for this agent
    policy.yaml             # Optional image policy source
```

Agent directories should contain agent-specific intent and payloads: manifests,
prompt templates, provider profiles, policies, and references to skills or
subagents. They should not contain `harnesses/codex`, `harnesses/opencode`, or
similar runtime code.

## Agent Manifest

Each agent has an `agent.yaml` manifest. The launcher currently reads these
sections:

- `id`, `display_name`, `description`: human and runtime identity.
- `sandbox`: default sandbox name prefix, gateway, source image or Dockerfile,
  and background log directory.
- `harness`: default harness and per-harness settings such as model and
  reasoning effort.
- `runtime`: in-sandbox run mode (`once` or `watch`), watch poll interval, and
  transient failure retry limit.
- `profile_paths`: ordered directories to scan for provider profile YAML files.
- `settings`: gateway settings to apply before launch.
- `providers`: provider instances to create or update, credential sources, and
  optional refresh configuration.
- `skills`: files to inject into the sandbox payload.
- `subagents`: subagent definitions to inject into the sandbox payload.
- `prompt_template`: prompt template rendered into `/sandbox/payload/agent-prompt.md`.

Manifest paths support these prefixes:

- `repo://path`: resolve from the repository root.
- `agent://path`: resolve from the agent directory.
- Relative paths without a prefix: resolve from the agent directory.
- Absolute paths: use as-is.

## Launch Order

`openshell-agents/run.sh` performs the launch in this order:

1. Parse CLI flags and select the agent directory from `--agent`.
2. Load `agent.yaml`, select the requested harness, and reject unsupported
   harness names.
3. Resolve sandbox defaults from the manifest and CLI/environment overrides.
4. Build a temporary payload directory.
5. Copy `runtime/` into the payload so every agent uses the same in-sandbox
   entrypoint and harness adapters.
6. Optionally copy a host Codex binary into the shared Codex runtime path when
   `--codex-bin` is supplied.
7. Copy manifest-declared skills and subagents into the payload.
8. Render the prompt template with runtime values such as `{{HARNESS}}`,
   `{{RUN_MODE}}`, `{{POLL_INTERVAL_SECONDS}}`, `{{SUBAGENT_COMMAND}}`, and
   `{{USER_PROMPT}}`.
9. Apply manifest-declared gateway settings.
10. Resolve provider profile IDs by scanning `profile_paths` in order.
11. Import each provider profile into the gateway. If an active profile already
    exists, the launcher keeps going and uses it.
12. Resolve provider credentials from host commands, JSON files, or literal
    manifest values.
13. Create or update each provider instance and attach every selected provider
    to the sandbox.
14. Configure and rotate refresh-backed provider credentials when declared by
    the manifest.
15. Run `openshell sandbox create` with the rendered payload uploaded to
    `/sandbox`.
16. Inside the sandbox, run `/sandbox/payload/runtime/entrypoint.sh`.
17. The runtime entrypoint starts `/sandbox/payload/runtime/supervisor.sh`.
18. The supervisor invokes `/sandbox/payload/runtime/harnesses/<harness>/exec.sh`
    as a bounded child execution.
19. Harness adapters prepare harness-local auth/config and execute the agent
    prompt headlessly.

## Runtime Modes

Agents can run in `once` or `watch` mode. In `once` mode the supervisor runs one
harness cycle and exits with the harness result unless the agent emits an
`OPENSHELL_AGENT_RESULT` sentinel.

In `watch` mode the sandbox stays alive while the supervisor repeatedly runs
bounded harness cycles. The harness must not sleep or poll indefinitely. Instead,
it performs one reconciliation cycle, then prints a final-line sentinel:

```text
OPENSHELL_AGENT_RESULT {"status":"waiting","next_poll_seconds":900,"reason":"checks_pending"}
```

Supported statuses are `complete`, `waiting`, `blocked`, `transient_failure`, and
`terminal_failure`. The supervisor sleeps between `waiting` or `blocked` cycles
without keeping the harness connected, then launches a fresh harness cycle inside
the same sandbox. This keeps long-lived agents resilient to harness transport
disconnects while leaving durable state ownership to the agent domain.

The shared runtime does not prescribe the durable state store. Gator uses GitHub
labels, comments, reviews, and checks. Other agents can use a repository branch,
issue tracker, object store, database, or another domain-specific store as long
as each cycle can reconcile from that state.

Use `--once` or `--watch` to override the manifest default. Use
`--poll-interval <seconds>` to override the watch sleep interval.

Refresh-backed providers are bootstrapped from manifest credential sources when
no gateway refresh state exists. Later launches preserve gateway-owned refresh
material and request a credential rotation first. If that rotation fails, the
launcher treats the host credential source as a repair source, replaces the
gateway refresh material, and retries rotation once. Use `--reset-refresh` to
skip the preserve-first path and intentionally replace gateway refresh material
from the host credential source before rotating.

## Subagents

The launcher injects subagent definitions under `/sandbox/payload/subagents/`.
Prompt templates should refer to the generic command instead of a harness-specific
script:

```shell
bash /sandbox/payload/runtime/subagent.sh <subagent-id> < task.md
```

The shared subagent dispatcher forwards the task to the active harness adapter.
For Codex, this runs a separate bounded `codex exec` invocation using the same
model and reasoning defaults as the parent harness.

## Providers

Listing a provider in `agent.yaml` means the provider is attached to the sandbox.
Provider profiles describe credential shape, endpoint policy, discovery metadata,
and refresh metadata. The launcher only creates provider instances and supplies
runtime credential values.

`profile_paths` are ordered. The first profile file with the requested `id` wins.
If the same directory contains duplicate profile IDs, the launcher fails. If a
later profile path contains a profile ID that was already found, the launcher
warns that the later file is shadowed.

## Gator Example

`gator/` is the first manifest-driven agent. It uses:

- `gator/agent.yaml` for the launch contract.
- `gator/prompts/gator.md` for the rendered operator prompt.
- `gator/providers/` for scoped GitHub and Codex provider profiles.
- `Dockerfile.gator` for the local sandbox image.
- `runtime/harnesses/codex/` for Codex installation and execution.

Run it through the generic launcher:

```shell
./openshell-agents/run.sh \
  --agent gator \
  --gateway docker-dev \
  "Run gator on PR 1536 and keep watching until it closes or merges."
```
