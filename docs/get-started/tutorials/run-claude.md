<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Run Claude Safely

Run Anthropic Claude as a coding agent inside a NemoClaw sandbox. This tutorial takes you from a fresh cluster to an interactive Claude session with credential management, inference routing, and policy enforcement.

## Prerequisites

- NemoClaw CLI installed. Refer to [Installation](../installation.md).
- Docker installed and running.
- An Anthropic API key available as `ANTHROPIC_API_KEY` in your environment or in `~/.claude.json`.

## Step 1: Deploy a Cluster

NemoClaw runs sandboxes on a lightweight Kubernetes cluster packaged in a single Docker container.

```console
$ nemoclaw cluster admin deploy
```

Verify that the cluster is healthy.

```console
$ nemoclaw cluster status
```

You should see the cluster version and a healthy status. If you already have a running cluster, skip this step.

## Step 2: Create a Claude Sandbox

The simplest way to start Claude in a sandbox auto-discovers your local credentials and drops you into an interactive shell.

```console
$ nemoclaw sandbox create --name my-claude -- claude
```

- `--name my-claude` — gives the sandbox a name for reconnection and management.
- `-- claude` — tells NemoClaw to auto-discover Anthropic credentials (`ANTHROPIC_API_KEY`, `CLAUDE_API_KEY`, `~/.claude.json`) and launch Claude inside the sandbox.

The CLI creates a provider from your local credentials, uploads them to the gateway, and opens an interactive SSH session into the sandbox.

### With File Sync and Additional Providers

For working on a project with GitHub access:

```console
$ nemoclaw sandbox create \
  --name my-claude \
  --provider my-github \
  --sync \
  -- claude
```

- `--provider my-github` — attaches a previously created GitHub provider (repeatable for multiple providers).
- `--sync` — pushes local git-tracked files to `/sandbox` in the container.

## Step 3: Work Inside the Sandbox

Once connected, you are inside an isolated environment. Provider credentials are available as environment variables.

```console
sandbox@my-claude:~$ echo $ANTHROPIC_API_KEY
sk-ant-...

sandbox@my-claude:~$ claude
```

The sandbox enforces its safety and privacy policy:

- Filesystem access is restricted to allowed directories.
- All network connections go through the policy-enforcing proxy.
- Only explicitly permitted hosts and programs can reach the internet.

## Step 4: Route Inference to a Private Model

By default, Claude's API calls go through the sandbox proxy. You can reroute them to a private or self-hosted model to keep prompts and responses on your own infrastructure.

### Create the Route

```console
$ nemoclaw inference create \
  --routing-hint local \
  --base-url https://integrate.api.nvidia.com/ \
  --model-id nvidia/nemotron-3-nano-30b-a3b \
  --api-key $NVIDIA_API_KEY
```

### Apply a Policy with the Route

Create a policy file `claude-policy.yaml`:

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
network_policies:
  anthropic:
    endpoints:
      - host: api.anthropic.com
        port: 443
    binaries:
      - path_patterns: ["**/claude"]
      - path_patterns: ["**/node"]
inference:
  allowed_routes:
    - local
```

This policy explicitly allows the Claude binary to reach `api.anthropic.com` and routes any other inference-shaped traffic to the `local` backend.

Update the running sandbox with the new policy.

```console
$ nemoclaw sandbox policy set my-claude --policy claude-policy.yaml --wait
```

Claude continues to work as normal — it still calls the Anthropic SDK as usual, but NemoClaw controls which requests go to the cloud and which are routed to your private model.

## Step 5: Monitor and Iterate on Policy

Watch sandbox logs to see which connections are allowed or denied.

```console
$ nemoclaw sandbox logs my-claude --tail --source sandbox
```

If Claude needs access to additional endpoints (for example, GitHub for code retrieval or npm for package installation), pull the current policy, add the missing entry, and push it back.

```console
$ nemoclaw sandbox policy get my-claude --full > current-policy.yaml
```

Edit `current-policy.yaml` to add a `network_policies` entry, then push it.

```console
$ nemoclaw sandbox policy set my-claude --policy current-policy.yaml --wait
```

Refer to [Policies](../../security/policies.md) for the full policy iteration workflow.

## Step 6: Reconnect or Open a Second Session

You can reconnect to the sandbox from any terminal.

```console
$ nemoclaw sandbox connect my-claude
```

For VS Code Remote-SSH access:

```console
$ nemoclaw sandbox ssh-config my-claude >> ~/.ssh/config
```

Then connect via VS Code's Remote-SSH extension to the host `my-claude`.

## Step 7: Verify Policy Enforcement

With Claude running inside the sandbox, confirm that the policy is doing its job.

### Test a Blocked Action

From inside the sandbox, attempt to reach an endpoint that is not in the policy.

```console
sandbox@my-claude:~$ curl https://example.com
```

The proxy blocks the connection because `example.com` is not in any `network_policies` entry and the request is not an inference API pattern. You should see a connection-refused or proxy-denied error.

### Test a Blocked File Access

Try to write to a read-only directory.

```console
sandbox@my-claude:~$ touch /usr/test-file
touch: cannot touch '/usr/test-file': Permission denied
```

Landlock prevents writes outside the `read_write` paths defined in your policy.

### Check the Denial in Logs

From your host, view the sandbox logs to see the deny entries.

```console
$ nemoclaw sandbox logs my-claude --tail --source sandbox
```

Look for log lines with `action: deny` showing the destination host, port, binary, and the reason. This confirms that the policy engine is evaluating every outbound connection and only allowing traffic that matches your policy.

### Confirm Claude Works Through Policy

Ask Claude to perform a task — for example, reading a file in `/sandbox` or writing code. Claude operates normally within the boundaries of the policy. If you configured an inference route in Step 4, the logs show whether inference calls were intercepted and routed to your private backend.

```console
sandbox@my-claude:~$ claude "List the files in /sandbox"
```

## Step 8: Clean Up

Delete the sandbox when you are finished to free cluster resources.

```console
$ nemoclaw sandbox delete my-claude
```

## Quick Reference

| Goal | How |
| ---- | --- |
| Launch Claude | `nemoclaw sandbox create --name my-claude -- claude` |
| Launch with file sync | `nemoclaw sandbox create --name my-claude --sync -- claude` |
| Reconnect | `nemoclaw sandbox connect my-claude` |
| Route inference to a private model | `nemoclaw inference create --routing-hint local --base-url <URL> --model-id <MODEL> --api-key <KEY>` and set `inference.allowed_routes: [local]` in policy |
| Update policy live | `nemoclaw sandbox policy set my-claude --policy updated.yaml --wait` |
| View logs | `nemoclaw sandbox logs my-claude --tail --source sandbox` |
| Delete | `nemoclaw sandbox delete my-claude` |

## Next Steps

- [Sandboxes](../../sandboxes/index.md) — full sandbox lifecycle management.
- [Providers](../../sandboxes/providers.md) — managing credentials and auto-discovery.
- [Inference Routing](../../inference/index.md) — route AI API calls to local or self-hosted backends.
- [Safety & Privacy](../../security/index.md) — understanding and customizing sandbox policies.
