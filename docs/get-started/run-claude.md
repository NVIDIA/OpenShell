<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Run Claude Code Safely

This tutorial walks you through the path to running Claude Code inside a OpenShell sandbox. By the end of this tutorial, you will have an isolated environment with credentials securely injected and a default policy controlling what the agent can access.

## What You Will Learn

- Create a sandbox with a single command.
- Understand how OpenShell auto-discovers provider credentials.
- Inspect what the default policy allows and denies.
- Connect to a running sandbox and work inside it.

## Prerequisites

- Met the prerequisites and installed the OpenShell CLI as described in the {doc}`quickstart` guide.
- `ANTHROPIC_API_KEY` environment variable set on your host machine.

## Create the Sandbox

Run the following command:

```console
$ openshell sandbox create -- claude
```

This single command performs four actions:

1. Bootstraps the runtime. On first use, the CLI provisions a local k3s cluster inside Docker and deploys the OpenShell control plane. This happens once. Subsequent commands reuse the existing cluster.
2. Auto-discovers credentials. The CLI detects that `claude` is a recognized tool and reads the `ANTHROPIC_API_KEY` environment variable from your shell. It creates a provider automatically.
3. Creates the sandbox. The CLI provisions an isolated container and applies the default policy. This policy allows Claude Code to reach `api.anthropic.com` and a small set of supporting endpoints while blocking everything else.
4. Drops you into the sandbox. You land in an interactive SSH session, ready to work.

:::{note}
The first bootstrap takes a few minutes depending on your network speed. The CLI prints progress as each component starts. Subsequent sandbox creations are much faster.
:::

## Work Inside the Sandbox

You are now inside the sandbox. Start Claude Code:

```console
$ claude
```

Your credentials are available as environment variables. Verify this with:

```console
$ echo $ANTHROPIC_API_KEY
sk-ant-...
```

The sandbox provides a working directory at `/sandbox` where you can create and edit files. Standard development tools — git, common language runtimes, and package managers — are available within the boundaries set by the policy.

## Check Sandbox Status

Open a second terminal on your host machine to inspect the sandbox from outside.

1. In the second terminal, list all sandboxes:

    ```console
    $ openshell sandbox list
    ```

2. Launch the OpenShell Terminal for a live dashboard that shows sandbox status, active network connections, and policy decisions in real time:

    ```console
    $ openshell term
    ```

## Connect from VS Code (Optional)

If you prefer a graphical editor, connect to the sandbox with VS Code Remote-SSH.

Export the sandbox SSH configuration:

```console
$ openshell sandbox ssh-config <sandbox-name> >> ~/.ssh/config
```

Then open VS Code, install the Remote - SSH extension if needed, and connect to the host named after your sandbox. VS Code opens a full editor session inside the isolated environment.

:::{tip}
Replace `<sandbox-name>` with your sandbox name. Run `openshell sandbox list` to find it if you did not specify one at creation time.
:::

## Clean Up

Exit the sandbox shell:

```console
$ exit
```

Delete the sandbox:

```console
$ openshell sandbox delete <name>
```

:::{tip}
If you want the sandbox to persist after you disconnect, add the `--keep` flag at creation time:

```console
$ openshell sandbox create --keep -- claude
```

This is useful when you plan to reconnect later or iterate on the policy while the sandbox runs.
:::

## Next Steps

- {doc}`../sandboxes/create-and-manage`: Learn the isolation model and sandbox lifecycle.
- {doc}`../sandboxes/providers`: Understand how credentials are injected without exposing them to agent code.
- {doc}`../safety-and-privacy/default-policies`: What the built-in default policy allows and denies.
- {doc}`../safety-and-privacy/policies`: Write custom policies and configure network rules.
