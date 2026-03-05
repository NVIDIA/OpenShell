<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Run AI Agents Safely inside NemoClaw

This tutorial shows how to run OpenClaw inside NemoClaw with zero code changes. You will learn how the platform delivers safe, autonomous, long-running agent execution through isolation, privacy routing, and declarative policy.

## Prerequisites

Before you begin, ensure the following are in place.

- NemoClaw CLI installed. Refer to [Installation](../installation.md).
- A running cluster. Run `nemoclaw cluster admin deploy` to create one.

## Why NemoClaw

Coding agents like OpenClaw run for hours, maintain state across sessions, spawn subagents, and build their own tools on the fly. Giving an agent persistent shell access, common developer tools, and the ability to spawn subagents against APIs that touch sensitive data is productive — but without an infrastructure layer, accumulated sensitive context leaks to a frontier model, unreviewed skills get filesystem and network access, and subagents inherit permissions they were never meant to have.

NemoClaw solves this by running any agent inside an isolated sandbox with zero code changes. Agents are isolated by default and controlled by policy.

## Run OpenClaw in One Command

You can run OpenClaw inside a NemoClaw sandbox with a single command. The sandbox image includes OpenClaw, the onboarding flow, and a helper script that configures the gateway and prints the access URL.

```console
$ nemoclaw sandbox create --forward 18789 -- openclaw-start
```

- `--forward 18789` — forwards sandbox port 18789 to your machine so the OpenClaw UI is available locally.
- `openclaw-start` — a script pre-installed in the sandbox that runs `openclaw onboard`, starts the gateway in the background, and prints the UI URL and token.

The CLI returns when the script finishes; the port forward keeps running in the background. Once it completes:

- **Control UI:** `http://127.0.0.1:18789/` (use the token printed during onboarding).
- **Health:** `openclaw health` from your host or inside the sandbox.

No changes are required in OpenClaw itself; it runs as-is inside the sandbox.

### What `openclaw-start` Does

Under the hood, the helper script does:

```bash
openclaw onboard
nohup openclaw gateway run > /tmp/gateway.log 2>&1 &
# Prints UI URL and token from ~/.openclaw/openclaw.json
```

### Step-by-Step Alternative

If you prefer to drive steps yourself (for example, for automation or debugging):

```console
$ nemoclaw sandbox create --keep --forward 18789
```

Then inside the sandbox:

```bash
openclaw onboard
nohup openclaw gateway run > /tmp/gateway.log 2>&1 &
exit
```

The sandbox stays up with the `--keep` flag, and the `--forward` flag gives you local access to the gateway.

## Long-Lived Sandboxes and File Sync

For development workflows, you can keep a sandbox running, sync in your repo, and run commands against it.

```console
$ nemoclaw sandbox create --name <agent-name> --keep --sync -- python main.py
```

- `--name <agent-name>`: Name of the sandbox for reuse with `nemoclaw sandbox connect <agent-name>`.
- `--sync`: Syncs git-tracked files into `/sandbox` before running the command.
- `--keep`: Leaves the sandbox running after the command (for example, for interactive use).

You can reconnect to the same environment later:

```console
$ nemoclaw sandbox connect my-agent
```

## How NemoClaw Delivers Safety

NemoClaw organizes controls around Access, Privacy, and Skills. Four primitives implement them.

### Gateway — Control Plane and Auth

The *Gateway* is the control-plane API that coordinates sandbox lifecycle and state, acts as the auth boundary, and brokers requests. Everything flows through it: sandbox create/delete, policy updates, inference route management, and policy and route delivery to sandboxes.

When you run `nemoclaw sandbox create -- openclaw-start`, the CLI talks to the Gateway to create the sandbox, attach policy, and (optionally) set up port forwarding. Sandboxes fetch their policy and inference bundle from the Gateway and report policy load status back.

### Sandbox — Isolation and Policy at the Edge

The *Sandbox* is the execution environment for long-running agents. It provides skill development and verification, programmable system and network isolation, and isolated execution so agents can break things without touching the host.

The sandbox is a supervised child process with:

- **Filesystem isolation** — Landlock with a policy-defined allowlist: read-only versus read-write paths (for example, `/sandbox` and `/tmp` writable; `/usr` and `/etc` read-only).
- **Process identity** — runs as an unprivileged user/group (for example, `sandbox:sandbox`).
- **Network** — in Proxy mode, the sandbox gets an isolated network namespace. All outbound TCP goes through an in-sandbox HTTP CONNECT proxy. Every connection is evaluated by the Policy Engine.
- **Policy updates** — the sandbox polls the Gateway for policy updates and applies them live at sandbox scope (network and inference rules only; filesystem/process are fixed at create time). You can approve new endpoints or routes without restarting the agent.

### Privacy Router and Inference Routing

The *Privacy Router* is a privacy-aware LLM routing layer that keeps sensitive context on sandbox (or on-prem) compute. Only non-sensitive work goes to frontier cloud models.

NemoClaw implements this as inference routing:

1. The sandbox intercepts outbound HTTPS from the agent (for example, OpenAI SDK, Anthropic SDK).
2. The proxy TLS-terminates, parses the request, and detects inference API patterns (for example, `POST /v1/chat/completions`, `POST /v1/messages`).
3. A route configuration maps a routing hint (for example, `local`) to a backend: base URL, model ID, protocol, and API key.
4. The proxy forwards the request to the allowed backend and returns the response to the agent. The agent's code does not change; it still targets `api.openai.com` or similar — NemoClaw rewrites destination and model as per policy.

You can point `local` to an on-prem model for private work and use other routes for cloud reasoning/planning. The router decides based on your cost and privacy policy, not the agent's.

#### Create an Inference Route

Use the CLI to create a route:

```console
$ nemoclaw inference create \
  --routing-hint local \
  --base-url https://integrate.api.nvidia.com/ \
  --model-id nvidia/nemotron-3-nano-30b-a3b \
  --api-key $NVIDIA_API_KEY
```

Then allow the route in sandbox policy:

```yaml
inference:
  allowed_routes:
    - local
```

Only routes listed in `allowed_routes` are available to that sandbox. Refer to [Inference Routing](../../inference/index.md) for the full configuration reference.

### Policy Engine — Granular, Explainable Enforcement

The *Policy Engine* handles policy definition and enforcement for filesystem, network, and process. Enforcement is out-of-process: the proxy and OPA/Rego run in the sandbox supervisor, not inside the agent process. The thing being guarded cannot bypass the guardrails; the constraints are structural, not behavioral.

Policy is expressed in a YAML file with five sections.

- `filesystem_policy`: lists directories the agent can read (`read_only`) or read and write (`read_write`). Set `include_workdir` to make the current working directory writable automatically.
- `landlock`: controls Linux Landlock LSM behavior. Use `compatibility: best_effort` to run with the best available kernel ABI.
- `process`: sets the unprivileged user and group the agent runs as (`run_as_user`, `run_as_group`).
- `network_policies`: defines named `network_policies` that pair specific binaries with the endpoints they may reach, identified by host, port, and protocol. Endpoints can include L7 HTTP rules that restrict allowed methods and paths, TLS termination, and an enforcement mode.
- `inference`: specifies which routing hints the sandbox may use through `allowed_routes`.

Every outbound connection is evaluated by destination, method, path, and binary. When inference routing is enabled, connections that do not match any network policy are inspected for inference. If they match a known inference API pattern, they are routed according to the inference configuration.

#### An Example of a Minimal Policy

```yaml
version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /etc, /app, /var/log]
  read_write: [/sandbox, /tmp, /dev/null]
landlock:
  compatibility: best_effort
process:
  run_as_user: sandbox
  run_as_group: sandbox
inference:
  allowed_routes:
    - local
```

In this example, there are no `network_policies`, which means no explicit allowlist. With `inference.allowed_routes` set, the engine treats unknown endpoints as "inspect for inference," and only inference-shaped traffic is allowed and routed.

Create a sandbox with this policy:

```console
$ nemoclaw sandbox create --policy ./policy-with-inference.yaml -- claude
```

## Live Policy Iteration

You can update network and inference policy on a running sandbox without restarting it.

```console
$ nemoclaw sandbox policy get my-agent --full > current-policy.yaml
# Edit current-policy.yaml to add a network_policy or inference route
$ nemoclaw sandbox policy set my-agent --policy current-policy.yaml --wait
```

Refer to [Policies](../../safety-and-privacy/policies.md) for the full policy iteration workflow.

## Next Steps

- [Sandboxes](../../sandboxes/index.md) — full sandbox lifecycle management.
- [Inference Routing](../../inference/index.md) — route AI API calls to local or self-hosted backends.
- [Safety & Privacy](../../safety-and-privacy/index.md) — understanding and customizing sandbox policies.
- [Network Access Control](../../safety-and-privacy/network-access-rules.md) — per-binary, per-endpoint network rules.
