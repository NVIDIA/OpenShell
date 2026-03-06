<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Run OpenCode with NVIDIA Inference

This tutorial walks through a realistic setup where you run [OpenCode](https://opencode.ai) inside a NemoClaw sandbox with inference routed to NVIDIA API endpoints. Along the way, you will hit policy problems, diagnose them from logs, write a custom policy, and configure inference routing. This is the full policy iteration loop.

**What you will learn:**

- Creating a provider manually with `--from-existing`
- Writing a custom policy to replace the defaults
- Reading sandbox logs to diagnose denied actions
- The difference between agent traffic and userland inference
- Setting up inference routes for code running inside the sandbox

## Prerequisites

Before you begin:

- `NVIDIA_API_KEY` environment variable set on your host machine with a valid NVIDIA API key
- NemoClaw CLI installed (`pip install nemoclaw`)

## Step 1: Create the Provider

Unlike the Claude Code tutorial where the CLI auto-discovered credentials, here you create a provider explicitly. This gives you control over the provider name and type.

```console
$ nemoclaw provider create --name nvidia --type nvidia --from-existing
```

The `--from-existing` flag tells the CLI to discover credentials from your local environment. It finds `NVIDIA_API_KEY` and stores it securely. The provider is now available to attach to any sandbox.

Verify the provider:

```console
$ nemoclaw provider list
```

## Step 2: Create the Sandbox

Create a sandbox with the NVIDIA provider attached and OpenCode as the startup command:

```console
$ nemoclaw sandbox create --name opencode-sandbox --provider nvidia --keep -- opencode
```

The `--keep` flag keeps the sandbox alive after you exit, which you will need for the iteration steps ahead. The CLI creates the sandbox with the default policy, injects the NVIDIA credentials, and starts OpenCode.

## Step 3: Hit a Problem

Try using OpenCode inside the sandbox. You will likely find that calls to NVIDIA inference endpoints fail or behave unexpectedly. The default policy is designed around Claude Code, not OpenCode.

Open a second terminal and check the logs:

```console
$ nemoclaw sandbox logs opencode-sandbox --tail
```

Or launch the NemoClaw Terminal for a live view:

```console
$ nemoclaw term
```

Look for lines like these in the output:

```
action=deny  host=integrate.api.nvidia.com  binary=/usr/local/bin/opencode  reason="no matching network policy"
action=deny  host=opencode.ai               binary=/usr/bin/node            reason="no matching network policy"
action=inspect_for_inference  host=integrate.api.nvidia.com  binary=/bin/bash
```

These log entries tell you exactly what the policy blocks and why.

## Step 4: Understand Why

The default policy has a `nvidia_inference` network policy entry, but it is configured for a narrow set of binaries, typically `/usr/local/bin/claude` and `/usr/bin/node`. If OpenCode makes HTTP calls through a different binary (its own binary, `curl`, or a shell subprocess), those connections do not match any policy rule and get denied.

There are two separate problems:

1. OpenCode's own traffic. OpenCode contacts `opencode.ai` for its API and `integrate.api.nvidia.com` for inference. Neither of these endpoints has a matching policy entry for the binaries OpenCode uses.
2. No opencode.ai endpoint. The default policy has no entry for `opencode.ai` at all. Even if the binary matched, the destination is not listed.

This is the expected behavior. NemoClaw denies by default. You need to write a policy that explicitly allows what OpenCode needs.

## Step 5: Write a Custom Policy

Create a file called `opencode-policy.yaml` with the following content:

```yaml
version: 1
inference:
  allowed_routes:
    - nvidia
filesystem_policy:
  include_workdir: true
  read_only:
    - /usr
    - /lib
    - /proc
    - /dev/urandom
    - /app
    - /etc
    - /var/log
  read_write:
    - /sandbox
    - /tmp
    - /dev/null
landlock:
  compatibility: best_effort
process:
  run_as_user: sandbox
  run_as_group: sandbox
network_policies:
  opencode_api:
    name: opencode-api
    endpoints:
      - host: opencode.ai
        port: 443
        protocol: rest
        tls: terminate
        enforcement: enforce
        access: full
    binaries:
      - path: /usr/local/bin/opencode
      - path: /usr/bin/node
  nvidia_inference:
    name: nvidia-inference
    endpoints:
      - host: integrate.api.nvidia.com
        port: 443
        protocol: rest
        tls: terminate
        enforcement: enforce
        access: full
    binaries:
      - path: /usr/local/bin/opencode
      - path: /usr/bin/node
      - path: /usr/bin/curl
      - path: /bin/bash
  npm_registry:
    name: npm-registry
    endpoints:
      - host: registry.npmjs.org
        port: 443
    binaries:
      - path: /usr/bin/npm
      - path: /usr/bin/node
      - path: /usr/local/bin/npm
      - path: /usr/local/bin/node
  github_rest_api:
    name: github-rest-api
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        tls: terminate
        enforcement: enforce
        access: read-only
    binaries:
      - path: /usr/local/bin/opencode
      - path: /usr/bin/node
      - path: /usr/bin/gh
  github_ssh_over_https:
    name: github-ssh-over-https
    endpoints:
      - host: github.com
        port: 443
        protocol: rest
        tls: terminate
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/**/info/refs*"
          - allow:
              method: POST
              path: "/**/git-upload-pack"
    binaries:
      - path: /usr/bin/git
```

Compared to the default policy, this adds:

- `opencode_api`: allows opencode and Node.js to reach `opencode.ai:443`
- Broader `nvidia_inference` binaries: adds `/usr/local/bin/opencode`, `/usr/bin/curl`, and `/bin/bash` so opencode's subprocesses can reach the NVIDIA endpoint
- `inference.allowed_routes`: includes `nvidia` so inference routing works for userland code
- GitHub access scoped for opencode's git operations

:::{warning}
The `filesystem_policy`, `landlock`, and `process` sections are static. They are set at sandbox creation time and cannot be changed on a running sandbox. If you need to modify these, you must delete and recreate the sandbox. The `network_policies` and `inference` sections are dynamic and can be hot-reloaded.
:::

## Step 6: Push the Policy

Apply your custom policy to the running sandbox:

```console
$ nemoclaw sandbox policy set opencode-sandbox --policy opencode-policy.yaml --wait
```

The `--wait` flag blocks until the sandbox confirms the policy is loaded. You will see output indicating success or failure.

Verify the policy revision was accepted:

```console
$ nemoclaw sandbox policy list opencode-sandbox
```

The latest revision should show status `loaded`.

## Step 7: Set Up Inference Routing

So far, you have allowed the opencode *agent* to reach `integrate.api.nvidia.com` directly through network policy. But what about code that opencode writes and runs inside the sandbox? If that code calls an LLM API, it goes through the privacy router: a separate mechanism.

Create an inference route so userland code can access NVIDIA models:

```console
$ nemoclaw inference create \
  --routing-hint nvidia \
  --base-url https://integrate.api.nvidia.com \
  --model-id z-ai/glm5 \
  --api-key $NVIDIA_API_KEY
```

The policy you wrote in Step 5 already includes `nvidia` in `inference.allowed_routes`, so you do not need to push a policy update. If you had not included it, you would add it to the policy and push again:

```console
$ nemoclaw sandbox policy set opencode-sandbox --policy opencode-policy.yaml --wait
```

:::{note}
The *network policies* control which hosts the agent binary can reach directly. The *inference routes* control where LLM API calls from userland code (scripts, notebooks, applications the agent writes) get routed. These are two separate enforcement points.
:::

## Step 8: Verify

Tail the logs again:

```console
$ nemoclaw sandbox logs opencode-sandbox --tail
```

You should no longer see `action=deny` lines for the endpoints you added. Connections to `opencode.ai`, `integrate.api.nvidia.com`, and GitHub should show `action=allow`.

If you still see denials, read the log line carefully. It tells you the exact host, port, and binary that was blocked. Add the missing entry to your policy and push again. This observe-modify-push cycle is the policy iteration loop, and it is the normal workflow for getting a new tool running in NemoClaw.

## Clean Up

When you are done:

```console
$ nemoclaw sandbox delete opencode-sandbox
```

## Next Steps

- {doc}`../../safety-and-privacy/policies`: Full reference on policy YAML structure, static and dynamic fields, and enforcement modes
- {doc}`../../safety-and-privacy/network-access-rules`: How the proxy evaluates network rules, L4 and L7 inspection, and TLS termination
- {doc}`../../inference/index`: Inference route configuration, protocol detection, and transparent rerouting
- {doc}`../../sandboxes/providers`: Provider types, credential discovery, and manual and automatic creation
- {doc}`../../safety-and-privacy/security-model`: The four protection layers and how they interact
