<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Run OpenCode with NVIDIA Inference

This tutorial walks you through a realistic setup where you run [OpenCode](https://opencode.ai) inside an OpenShell sandbox and configure private inference through `inference.local`. Along the way, you will hit a policy denial, diagnose it from logs, write a custom policy, and configure inference routing. This is the full policy iteration loop that you will use whenever you onboard a new tool.

## What You Will Learn

- Create a provider manually using the `--from-existing` flag.
- Write a custom policy to replace the default policy.
- Read sandbox logs to diagnose denied actions.
- Distinguish between agent traffic and sandbox inference traffic.
- Configure inference routing for code running inside the sandbox.

## Prerequisites

- Met the prerequisites and installed the OpenShell CLI as described in the {doc}`quickstart` guide.
- `NVIDIA_API_KEY` environment variable set on your host machine with a valid NVIDIA API key.

## Create the Provider

In the Claude Code tutorial, the CLI auto-discovers credentials. Here you create a provider explicitly, which gives you control over the provider name and type.

```console
$ openshell provider create --name nvidia --type nvidia --from-existing
```

The `--from-existing` flag tells the CLI to discover credentials from your local environment. It finds `NVIDIA_API_KEY` and stores it securely. The provider is now available to attach to any sandbox.

Verify the provider exists:

```console
$ openshell provider list
```

## Create the Sandbox

Create a sandbox with the NVIDIA provider attached and OpenCode as the startup command:

```console
$ openshell sandbox create --name opencode-sandbox --provider nvidia --keep -- opencode
```

The `--keep` flag keeps the sandbox alive after you exit, which you need for the iteration steps ahead. The CLI creates the sandbox with the default policy, injects the NVIDIA credentials, and starts OpenCode.

## Hit a Policy Denial

Try using OpenCode inside the sandbox. You will find that calls to NVIDIA inference endpoints fail. The default policy is designed around Claude Code, not OpenCode, so the required endpoints are not allowlisted.

Open a second terminal and check the logs:

```console
$ openshell logs opencode-sandbox --tail
```

Alternatively, launch the OpenShell Terminal for a live view:

```console
$ openshell term
```

Look for lines like these:

```text
action=deny  host=integrate.api.nvidia.com  binary=/usr/local/bin/opencode  reason="no matching network policy"
action=deny  host=opencode.ai               binary=/usr/bin/node            reason="no matching network policy"
```

Each log entry tells you the exact host, binary, and reason for the denial.

## Understand the Denial

The default policy contains a `nvidia_inference` network policy entry, but it is configured for a narrow set of binaries - typically `/usr/local/bin/claude` and `/usr/bin/node`. When OpenCode makes HTTP calls through its own binary, `curl`, or a shell subprocess, those connections do not match any policy rule and get denied.

Two separate problems are at play:

- OpenCode's own traffic. OpenCode contacts `opencode.ai` for its API and `integrate.api.nvidia.com` for inference. Neither endpoint has a matching rule for the binaries OpenCode uses.
- Missing endpoint. The default policy has no entry for `opencode.ai` at all. Even if the binary matched, the destination is not listed.

This is expected behavior. OpenShell denies everything by default. You need to write a policy that explicitly allows what OpenCode needs.

## Write a Custom Policy

Create a file called `opencode-policy.yaml` with the following content:

```yaml
version: 1
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

This policy differs from the default in three key ways:

- `opencode_api`: Allows OpenCode and Node.js to reach `opencode.ai:443`.
- Broader `nvidia_inference` binaries: Adds `/usr/local/bin/opencode`, `/usr/bin/curl`, and `/bin/bash` so OpenCode's subprocesses can reach the NVIDIA endpoint.
- GitHub access: Scoped to support OpenCode's git operations.

:::{warning}
The `filesystem_policy`, `landlock`, and `process` sections are static. They are set at sandbox creation time and cannot be changed on a running sandbox. To modify these, delete and recreate the sandbox. The `network_policies` section is dynamic and can be hot-reloaded.
:::

## Apply the Policy

Push your custom policy to the running sandbox:

```console
$ openshell policy set opencode-sandbox --policy opencode-policy.yaml --wait
```

The `--wait` flag blocks until the sandbox confirms the policy is loaded.

Verify the policy revision was accepted:

```console
$ openshell policy list opencode-sandbox
```

The latest revision should show status `loaded`.

## Configure Inference Routing

So far, you have allowed the OpenCode *agent* to reach `integrate.api.nvidia.com` directly through network policy. But code that OpenCode writes and runs inside the sandbox should use `https://inference.local`.

Configure inference so `inference.local` routes to your NVIDIA provider:

```console
$ openshell inference set \
  --provider nvidia \
  --model z-ai/glm5
```

Verify the active configuration:

```console
$ openshell inference get
```

:::{note}
*Network policies* and managed inference are two separate enforcement points. Network policies control which external hosts the agent binary can reach directly. Inference configuration controls where userland calls to `https://inference.local` are routed.
:::

## Verify the Policy

Tail the logs again:

```console
$ openshell logs opencode-sandbox --tail
```

You should see `action=allow` lines for the endpoints you added. Connections to `opencode.ai`, `integrate.api.nvidia.com`, and GitHub should show `action=allow`.

To verify userland inference, run code inside the sandbox that targets `https://inference.local/v1`.

If you still see denials, read the log line carefully. It tells you the exact host, port, and binary that was blocked. Add the missing entry to your policy and push again with `openshell policy set`. This observe-modify-push cycle is the normal workflow for onboarding any new tool in OpenShell.

## Clean Up

When you are finished, delete the sandbox:

```console
$ openshell sandbox delete opencode-sandbox
```

## Next Steps

- {doc}`../safety-and-privacy/policies`: Full reference on policy YAML structure, static and dynamic fields, and enforcement modes.
- {doc}`../safety-and-privacy/policies`: How network policy fits into the sandbox iteration workflow.
- {doc}`../inference/index`: `inference.local`, supported API patterns, and request routing.
- {doc}`../sandboxes/providers`: Provider types, credential discovery, and manual and automatic creation.
- {doc}`../safety-and-privacy/index`: The four protection layers and how they interact.
