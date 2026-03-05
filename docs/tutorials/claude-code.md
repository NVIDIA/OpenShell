<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Launch Claude Code

This tutorial walks you through the simplest path to running Claude Code inside a NemoClaw sandbox. By the end, you will have an isolated environment with Claude Code running, your credentials securely injected, and a default policy controlling what the agent can access.

**What you will learn:**

- Creating a sandbox with a single command
- How NemoClaw auto-discovers provider credentials
- What the default policy allows and denies
- Connecting to a sandbox and working inside it

## Step 1: Install NemoClaw

Install the CLI from PyPI:

```console
$ pip install nemoclaw
```

:::{tip}
You also need Docker running on your machine.
:::

## Step 2: Create a Sandbox

Run the following command:

```console
$ nemoclaw sandbox create -- claude
```

This single command does several things:

1. **Bootstraps the runtime.** If this is your first time using NemoClaw, the CLI provisions a local k3s cluster inside Docker and deploys the NemoClaw control plane. This happens once --- subsequent commands reuse the existing cluster.
2. **Auto-discovers credentials.** The CLI detects that `claude` is a recognized tool and looks for your Anthropic credentials. It reads the `ANTHROPIC_API_KEY` environment variable and creates a provider automatically.
3. **Creates the sandbox.** An isolated environment is provisioned with the default policy applied. The policy allows Claude Code to reach `api.anthropic.com` and a small set of supporting endpoints while blocking everything else.
4. **Drops you into the sandbox.** You land in an interactive SSH session inside the sandbox, ready to work.

:::{note}
The first bootstrap takes a few minutes depending on your network speed. The CLI prints progress as each component starts. Subsequent sandbox creations are much faster.
:::

## Step 3: Work Inside the Sandbox

You are now in an SSH session inside the sandbox. Start Claude Code:

```console
$ claude
```

Your credentials are available as environment variables inside the sandbox. You can verify this:

```console
$ echo $ANTHROPIC_API_KEY
sk-ant-...
```

The sandbox has a working directory at `/sandbox` where you can create and edit files. Claude Code has access to standard development tools --- git, common language runtimes, and package managers --- within the boundaries set by the policy.

## Step 4: Check Sandbox Status

Open a second terminal on your host machine. You can inspect running sandboxes from there.

List all sandboxes:

```console
$ nemoclaw sandbox list
```

For a live dashboard view, launch Gator:

```console
$ nemoclaw gator
```

Gator shows sandbox status, active network connections, and policy decisions in real time.

## Step 5: Connect from VS Code

If you prefer to work in VS Code rather than a terminal, you can connect via Remote-SSH.

First, export the sandbox's SSH configuration:

```console
$ nemoclaw sandbox ssh-config my-sandbox >> ~/.ssh/config
```

Then open VS Code, install the **Remote - SSH** extension if you have not already, and connect to the host named `my-sandbox`. VS Code opens a full editor session inside the sandbox.

:::{tip}
Replace `my-sandbox` with the actual name of your sandbox. Run `nemoclaw sandbox list` to find it if you did not specify a name at creation time.
:::

## Step 6: Clean Up

When you are done, exit the sandbox shell:

```console
$ exit
```

Then delete the sandbox:

```console
$ nemoclaw sandbox delete my-sandbox
```

:::{tip}
Use the `--keep` flag when you want the sandbox to stay alive after the command exits. This is useful when you plan to connect later or want to iterate on the policy while the sandbox runs.

```console
$ nemoclaw sandbox create --keep -- claude
```
:::

## Next Steps

- {doc}`../sandboxes/create-and-manage` --- understand the isolation model and sandbox lifecycle
- {doc}`../sandboxes/providers` --- how credentials are injected without exposing them to agent code
- {doc}`../safety-and-privacy/policies` --- learn how the default policy works and how to customize it
- {doc}`../safety-and-privacy/network-access-rules` --- dig into the network proxy and per-endpoint rules
