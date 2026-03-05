<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Your First Sandbox

This walkthrough takes you from a fresh install to an interactive sandbox session. By the end, you will have a running AI agent inside an isolated environment with full policy enforcement.

## Step 1: Bootstrap a Cluster

NemoClaw runs sandboxes on a lightweight Kubernetes cluster. If you don't have a cluster running yet, deploy one with a single command.

```console
$ nemoclaw cluster admin deploy
```

This provisions a local k3s cluster inside a Docker container. The cluster is automatically set as the active cluster.

For remote deployment (running the cluster on a different machine):

```console
$ nemoclaw cluster admin deploy --remote user@host --ssh-key ~/.ssh/id_rsa
```

### Verify the Cluster

Check that the cluster is running and healthy before you continue.

```console
$ nemoclaw cluster status
```

You should see the cluster version and a healthy status.

## Step 2: Set Up Providers

Providers supply credentials to sandboxes (API keys, tokens, etc.). When you use `nemoclaw sandbox create -- claude`, the CLI auto-discovers local Claude credentials and creates a provider for you. You can also set up providers manually:

```console
$ nemoclaw provider create --name my-claude --type claude --from-existing
```

The `--from-existing` flag scans your local machine for credentials (environment variables like `ANTHROPIC_API_KEY`, config files like `~/.claude.json`).

To see what providers you have:

```console
$ nemoclaw provider list
```

## Step 3: Create a Sandbox

The simplest way to get a sandbox running:

```console
$ nemoclaw sandbox create -- claude
```

This creates a sandbox with defaults, auto-discovers and uploads your Claude credentials, and drops you into an interactive shell.

### With More Options

You can name the sandbox, attach multiple providers, and sync your local project files in a single command.

```console
$ nemoclaw sandbox create \
  --name my-sandbox \
  --provider my-claude \
  --provider my-github \
  --sync \
  -- claude
```

- `--name` — give the sandbox a specific name.
- `--provider` — attach providers explicitly (repeatable).
- `--sync` — push local git-tracked files to `/sandbox` in the container.

## Step 4: Work Inside the Sandbox

Once connected, you are inside an isolated environment. All provider credentials are available as environment variables:

```console
sandbox@my-sandbox:~$ echo $ANTHROPIC_API_KEY
sk-ant-...

sandbox@my-sandbox:~$ claude
```

The sandbox enforces its safety and privacy policy:
- Your data is protected — filesystem access is restricted to allowed directories.
- No data leaves unmonitored — network connections go through the privacy-enforcing proxy.
- Only explicitly permitted hosts and programs can reach the internet.

## Step 5: Connect from Another Terminal

You can reconnect to a running sandbox at any time. This is useful if you closed your terminal or need a second session.

```console
$ nemoclaw sandbox connect my-sandbox
```

For VS Code Remote-SSH access:

```console
$ nemoclaw sandbox ssh-config my-sandbox >> ~/.ssh/config
```

Then connect via VS Code's Remote-SSH extension to the host `my-sandbox`.

## Step 6: Clean Up

Delete the sandbox when you are finished to free cluster resources.

```console
$ nemoclaw sandbox delete my-sandbox
```

## Next Steps

Now that you have a working sandbox, explore these areas to go further.

- [Sandboxes](../sandboxes/index.md) — full sandbox lifecycle management.
- [Providers](../sandboxes/providers.md) — managing credentials.
- [Safety & Privacy](../security/index.md) — understanding and customizing sandbox policies.
