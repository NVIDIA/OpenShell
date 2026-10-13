---
name: openshell-cli
description: Guide agents through using the OpenShell CLI (openshell) for sandbox management, gateway registration, provider configuration and refresh, profile management, policy iteration, settings, service exposure, BYOC workflows, and attached-provider inference. Covers basic through advanced multi-step workflows. Trigger keywords - openshell, sandbox create, sandbox exec, sandbox connect, logs, provider create, profile list, profile describe, provider refresh, policy set, policy get, settings, service expose, forward, port forward, BYOC, bring your own container, inference, use openshell, run openshell, CLI usage, agent context, manage sandbox, manage provider, gateway add, gateway select.
---

# OpenShell CLI

The `openshell` CLI manages gateway registrations, sandboxes, providers, policies, settings, and exposed services. Packages, systemd, or Helm run the gateway service itself.

## Start with the CLI map

```shell
openshell agent context
```

The map lists every command of the installed CLI with its usage line and summary, and every flag with its allowed values, default, environment variable, and the flags it cannot be combined with. It is generated from the binary, so when it disagrees with this skill, follow the map. Read all of it.

Each step costs a round trip, so batch your reads:

- Run the map and read every [workflow reference](#workflow-references) your task needs in the same step, with one call per file. Printed together, they are too large for one tool result.
- Run `openshell <group> <cmd> --help` only when the map and references leave a flag's meaning unclear, and combine those calls into one command.

## Rules for every command

- **Name the sandbox.** Most commands default to the last-used sandbox. Pass the name explicitly.
- **Use structured output in automation.** Prefer `--output json`. A few commands use `--json` instead, such as `settings get`; the map shows which.
- **Keep secrets out of arguments.** Never pass API keys or tokens with `--env`, `--credential KEY=VALUE`, or a command argument. Store them in a provider (`--credential KEY` reads the environment variable `KEY`) and attach it with `--provider`.
- **Use DNS-1123 sandbox names.** At most 63 lowercase alphanumeric or `-` characters, starting and ending with an alphanumeric character.
- **Upload, then run.** `sandbox create` cannot combine `--upload` with a trailing command. Create the sandbox with `--upload`, adding `--detach` when nothing needs to attach, then run the command with `sandbox exec`.
- **Delete explicitly when `--no-keep` can't be used.** `--no-keep` conflicts with `--editor`, `--forward`, and `--expose`. When the user wants cleanup after such a session, have them run `openshell sandbox delete <name>` afterwards.
- **Wait for changes that the next step needs.** Add `--wait` to policy and provider changes when later work depends on them. Without it, success only means the gateway saved the change.
- **Inspect before retrying.** `deletion accepted`, `CONFIG_OPERATION_STORAGE_UNCERTAIN`, and `sandbox exec` exit code 74 leave the outcome uncertain. Check the current state before running the mutation again.
- **Treat global changes as high impact.** `--global` policy and settings changes affect every sandbox and prompt for confirmation. Use `--yes` only in reviewed automation.
- **Target another gateway per command.** Use the global `--gateway <name>` (or `OPENSHELL_GATEWAY`) instead of `gateway select` when the user doesn't want to switch the active gateway.

## Concepts

- **Gateway**: the control plane. Register it with `gateway add`, pick one with `gateway select`, and check it with `status` and `whoami`.
- **Sandbox**: runs one canonical main process, by default `/bin/bash -l`. `sandbox create` attaches to it unless you pass `--detach`. `sandbox connect` reattaches to it, and `sandbox exec` starts a separate process. `stop` keeps the workspace, `start` relaunches, and `delete` removes everything.
- **Provider**: credentials and configuration built from a profile. `profile list` shows the profiles the gateway imported, and `--type` must match a profile ID exactly. Attach providers with `--provider` at create time or with `sandbox provider attach`.
- **Policy**: `filesystem_policy`, `landlock`, and `process` are fixed once the sandbox starts. `network_policies` and `network_middlewares` change live through `policy update` or `policy set`. Check a policy file locally with `policy validate` before you apply it. `sandbox get <name> --policy-only` prints a sandbox's active policy YAML.
- **Access**: `forward start` forwards a local port to the same port in the sandbox. `forward service` maps any local port to a loopback service in the sandbox. `service expose` publishes an HTTP endpoint through the gateway.
- **Rule proposals**: agents in a sandbox can propose network rules. Review them with `openshell rule` (`get`, `approve`, `reject`, `history`). This command is hidden from the map and from `--help`.

## Workflow references

Single commands need only the map. Read the matching reference before a multi-step workflow, before changing credentials or policy, or when a command fails:

| Task | Reference |
|------|-----------|
| First sandbox, create options, templates, connect and exec, files, attached providers, logs, stop, start, delete | [references/sandboxes.md](references/sandboxes.md) |
| Profiles, provider credentials, credential errors, refresh | [references/providers.md](references/providers.md) |
| Policy iteration loop, incremental updates, revision history, global policy, rule proposals | [references/policy.md](references/policy.md) |
| Gateway registration and authentication, gateway inspection, settings | [references/gateways.md](references/gateways.md) |
| Custom images (BYOC), port forwarding, exposed services, inference providers | [references/services.md](references/services.md) |

## Product documentation

Use the published documentation for concepts the CLI does not explain:

- [Manage gateways](https://docs.nvidia.com/openshell/latest/how-it-works/gateways/overview)
- [Manage sandboxes](https://docs.nvidia.com/openshell/latest/how-it-works/sandboxes/overview)
- [Manage providers](https://docs.nvidia.com/openshell/latest/how-it-works/providers/overview)
- [Profiles](https://docs.nvidia.com/openshell/latest/how-it-works/providers/profiles)
- [Sandbox policies](https://docs.nvidia.com/openshell/latest/how-it-works/policies/overview)
- [Inference routing](https://docs.nvidia.com/openshell/latest/how-it-works/inference)

Install the CLI with the [installation guide](https://docs.nvidia.com/openshell/latest/about/installation.md) when `openshell` is not on the PATH. Workflows also need a reachable gateway backed by Docker, Podman, Kubernetes, or the experimental VM driver; a local container engine for BYOC image builds; and `kubectl` and Helm access for Kubernetes deployments.

## Companion skills

| Skill | When to use |
|-------|------------|
| `generate-sandbox-policy` | Creating or modifying policy YAML content (network rules, L7 inspection, access presets, endpoint configuration, and network middleware) |
| `debug-openshell-cluster` | Diagnosing gateway deployment, runtime, or health failures |
| `debug-inference` | Diagnosing attached-provider inference, native endpoints, host-backed models, and migration from the retired managed endpoint |
