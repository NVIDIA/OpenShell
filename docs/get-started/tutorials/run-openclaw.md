<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Run OpenClaw Safely

Run OpenClaw inside a NemoClaw sandbox with zero code changes. This tutorial takes you from a fresh cluster to an OpenClaw instance with inference routing and policy enforcement.

## Prerequisites

- NemoClaw CLI installed. Refer to [Installation](../installation.md).
- Docker installed and running.

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

## Step 2: Launch OpenClaw

The sandbox image includes OpenClaw, the onboarding flow, and a helper script that configures the gateway and prints the access URL. One command starts everything.

```console
$ nemoclaw sandbox create --name my-openclaw --forward 18789 -- openclaw-start
```

- `--name my-openclaw` — gives the sandbox a name for reconnection and management.
- `--forward 18789` — forwards sandbox port 18789 to your machine so the OpenClaw UI is reachable locally.
- `openclaw-start` — runs `openclaw onboard`, starts the OpenClaw gateway in the background, and prints the UI URL and token.

The CLI returns when the script finishes. The port forward keeps running in the background.

## Step 3: Access the OpenClaw UI

Once the sandbox is ready, open the Control UI and verify health.

- **Control UI:** `http://127.0.0.1:18789/` — use the token printed during onboarding.
- **Health check:** run `openclaw health` from your host or inside the sandbox.

No changes are required in OpenClaw itself. It runs as-is inside the sandbox with full isolation.

### What `openclaw-start` Does

Under the hood, the helper script runs:

```bash
openclaw onboard
nohup openclaw gateway run > /tmp/gateway.log 2>&1 &
```

It then prints the UI URL and token from `~/.openclaw/openclaw.json`.

## Step 4: Route Inference to a Private Model

By default, the sandbox blocks outbound traffic that does not match an explicit network policy. To route OpenClaw's inference calls to a private or self-hosted model, create an inference route and allow it in sandbox policy.

### Create the Route

```console
$ nemoclaw inference create \
  --routing-hint local \
  --base-url https://integrate.api.nvidia.com/ \
  --model-id nvidia/nemotron-3-nano-30b-a3b \
  --api-key $NVIDIA_API_KEY
```

### Apply a Policy with the Route

Create a policy file `openclaw-policy.yaml`:

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

Update the running sandbox with the new policy.

```console
$ nemoclaw sandbox policy set my-openclaw --policy openclaw-policy.yaml --wait
```

OpenClaw's inference calls are now transparently intercepted and routed to the configured backend. The agent's code does not change — it still targets the original API, and NemoClaw rewrites the destination and model per policy.

## Step 5: Monitor and Iterate on Policy

Watch sandbox logs to see which connections are allowed or denied.

```console
$ nemoclaw sandbox logs my-openclaw --tail --source sandbox
```

If you see denied actions that should be allowed, pull the current policy, add the missing network policy entry, and push it back.

```console
$ nemoclaw sandbox policy get my-openclaw --full > current-policy.yaml
```

Edit `current-policy.yaml` to add a `network_policies` entry for the denied endpoint, then push it.

```console
$ nemoclaw sandbox policy set my-openclaw --policy current-policy.yaml --wait
```

Refer to [Policies](../../security/policies.md) for the full policy iteration workflow.

## Step 6: Reconnect or Open a Second Session

You can reconnect to the sandbox from any terminal.

```console
$ nemoclaw sandbox connect my-openclaw
```

For VS Code Remote-SSH access:

```console
$ nemoclaw sandbox ssh-config my-openclaw >> ~/.ssh/config
```

Then connect via VS Code's Remote-SSH extension to the host `my-openclaw`.

## Step 7: Verify Policy Enforcement

With the sandbox running and the OpenClaw UI accessible, confirm that the policy is doing its job.

### Confirm the UI Is Accessible

Open `http://127.0.0.1:18789/` in your browser and sign in with the token printed during onboarding. You should see the OpenClaw control dashboard.

### Test a Blocked Action

From inside the sandbox, attempt to reach an endpoint that is not in the policy.

```console
sandbox@my-openclaw:~$ curl https://example.com
```

The proxy blocks the connection because `example.com` is not in any `network_policies` entry and the request is not an inference API pattern. You should see a connection-refused or proxy-denied error.

### Check the Denial in Logs

From your host, view the sandbox logs to see the deny entry.

```console
$ nemoclaw sandbox logs my-openclaw --tail --source sandbox
```

Look for a log line with `action: deny` showing the destination host, port, binary (`curl`), and the reason. This confirms that the policy engine is evaluating every outbound connection and only allowing traffic that matches your policy.

### Confirm Inference Routing

If you configured an inference route in Step 4, ask OpenClaw to perform a task that triggers an inference call through the UI. The logs show whether the request was intercepted and routed to your configured backend rather than the original API endpoint.

## Step 8: Clean Up

Delete the sandbox when you are finished to free cluster resources.

```console
$ nemoclaw sandbox delete my-openclaw
```

## Quick Reference

| Goal | How |
| ---- | --- |
| Launch OpenClaw | `nemoclaw sandbox create --name my-openclaw --forward 18789 -- openclaw-start` |
| Reconnect | `nemoclaw sandbox connect my-openclaw` |
| Route inference to a private model | `nemoclaw inference create --routing-hint local --base-url <URL> --model-id <MODEL> --api-key <KEY>` and set `inference.allowed_routes: [local]` in policy |
| Update policy live | `nemoclaw sandbox policy set my-openclaw --policy updated.yaml --wait` |
| View logs | `nemoclaw sandbox logs my-openclaw --tail --source sandbox` |
| Delete | `nemoclaw sandbox delete my-openclaw` |

## Next Steps

- [Sandboxes](../../sandboxes/index.md) — full sandbox lifecycle management.
- [Inference Routing](../../inference/index.md) — route AI API calls to local or self-hosted backends.
- [Safety & Privacy](../../security/index.md) — understanding and customizing sandbox policies.
- [Network Access Control](../../security/network-access.md) — per-binary, per-endpoint network rules.
