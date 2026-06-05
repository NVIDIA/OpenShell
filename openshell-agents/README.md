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
    entrypoint.sh           # Dispatches to the selected harness adapter
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
   `{{SUBAGENT_COMMAND}}`, and `{{USER_PROMPT}}`.
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
17. The runtime entrypoint dispatches to
    `/sandbox/payload/runtime/harnesses/<harness>/exec.sh`.
18. Harness adapters prepare harness-local auth/config and execute the agent
    prompt headlessly.

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
