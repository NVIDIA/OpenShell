<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Run Claude Code Safely

Create a sandbox with Claude Code: isolated environment, credentials injected, default policy applied. The default policy allows the Anthropic API, GitHub read-only (clone/fetch), and common development endpoints; other traffic is denied.

## Prerequisites

- **Docker** running (required for the OpenShell runtime). See {doc}`quickstart` for details.
- **OpenShell CLI** installed (`pip install openshell` or from source).
- **`ANTHROPIC_API_KEY`** set in your environment on the host.

## Create the Sandbox

```console
$ openshell sandbox create -- claude
```

This command:

1. Bootstraps the runtime (on first use: provisions a local k3s cluster in Docker; subsequent runs reuse it).
2. Auto-discovers credentials from `ANTHROPIC_API_KEY` and creates a provider.
3. Creates the sandbox with the default policy and drops you into an interactive SSH session.

:::{note}
First bootstrap can take a few minutes. Later sandbox creations are much faster.
:::

## Work Inside the Sandbox

Start Claude Code:

```console
$ claude
```

Credentials are available as environment variables (e.g. `echo $ANTHROPIC_API_KEY`). Use `/sandbox` as the working directory. Git and common runtimes are available within policy limits.

## Check Sandbox Status

From a second terminal on the host:

```console
$ openshell sandbox list
```

For a live dashboard (status, connections, policy decisions):

```console
$ openshell term
```

## Connect from VS Code (Optional)

Export SSH config, then connect with Remote-SSH to the host named after your sandbox:

```console
$ openshell sandbox ssh-config <name> >> ~/.ssh/config
```

Use `<name>` from `openshell sandbox list`, or the name you passed to `--name` at creation.

## Clean Up

Exit the sandbox shell (`exit` or Ctrl-D), then:

```console
$ openshell sandbox delete <name>
```

Use the sandbox name from `openshell sandbox list` or the one you set with `--name`.

:::{tip}
To keep the sandbox running after you disconnect, create with `--keep`:

```console
$ openshell sandbox create --keep -- claude
```
:::

## Next Steps

- {doc}`../sandboxes/create-and-manage`: Sandbox lifecycle and isolation model.
- {doc}`../sandboxes/providers`: How credentials are injected.
- {doc}`../safety-and-privacy/policies`: Customize or replace the default policy.
- [Write Sandbox Policies (network access rules)](../safety-and-privacy/policies.md#network-access-rules): Network proxy and per-endpoint rules.
