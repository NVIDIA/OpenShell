<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Run OpenClaw Inside a NemoClaw Sandbox

This tutorial shows you how to launch a community sandbox using the `--from` flag. Community sandboxes are pre-built configurations published to the [NemoClaw Community](https://github.com/NVIDIA/NemoClaw-Community) repository. They bundle a container image, a tailored policy, and optional skills into a single package you can run with one command.

## What you will learn

You will learn the following from this tutorial:

- What community sandboxes are and how they differ from default sandboxes
- How to use the `--from` flag to pull and build a complete sandbox configuration
- How to inspect the bundled policy that ships with a community sandbox

## Prerequisites

Before you begin, make sure you have:

- Docker running on your machine.
- NVIDIA GPU with drivers installed. Required for GPU-accelerated workloads in the OpenClaw sandbox.
- [NemoClaw CLI installed](quickstart.md#install-the-nemoclaw-cli)

## Step 1: Create a Sandbox from the Community Image

Run the following command:

```console
$ nemoclaw sandbox create --from openclaw --keep
```

The `--from` flag tells the CLI to pull a sandbox definition from the NemoClaw Community catalog. Here is what happens:

1. Fetches the definition. The CLI downloads the OpenClaw sandbox definition from the NemoClaw-Community repository. This includes a Dockerfile, a policy YAML, and any bundled skills.
2. Builds the image. The CLI builds the Dockerfile locally using Docker. The image includes all tools and dependencies that OpenClaw needs.
3. Applies the bundled policy. Instead of the generic default policy, the sandbox starts with a policy specifically written for the OpenClaw workload. It allows the endpoints and binaries that OpenClaw requires.
4. Creates and keeps the sandbox. The `--keep` flag ensures the sandbox stays running after creation so you can connect and disconnect freely.

:::{note}
The first build takes longer because Docker needs to pull base layers and install dependencies. Subsequent creates reuse the cached image.
:::

## Step 2: Connect to the Sandbox

After the sandbox is running, connect to it:

```console
$ nemoclaw sandbox connect <name>
```

Replace `<name>` with the sandbox name shown in the creation output. If you did not specify a name with `--name`, the CLI assigns one automatically. Run `nemoclaw sandbox list` to find it.

## Step 3: Explore the Environment

The sandbox comes pre-configured for the OpenClaw workload. The tools, runtimes, and libraries that OpenClaw needs are already installed in the container image. The policy is tuned to allow the specific network endpoints and operations that OpenClaw uses, so you can start working immediately without policy adjustments.

## Step 4: Check the Bundled Policy

To see exactly what the sandbox is allowed to do, pull the full policy:

```console
$ nemoclaw sandbox policy get <name> --full
```

This outputs the complete policy YAML, including:

- Network policies: which hosts and ports the sandbox can reach, and which binaries are allowed to initiate those connections
- Filesystem policy: which paths are read-only and which are read-write
- Process restrictions: the user and group the sandbox runs as
- Inference rules: which inference routing hints are allowed

Reviewing the bundled policy is a good way to understand what a community sandbox has access to before you start using it for sensitive work.

:::{tip}
You can save the policy to a file for reference or as a starting point for customization:

```console
$ nemoclaw sandbox policy get <name> --full > openclaw-policy.yaml
```
:::

## Step 5: Clean Up

When you are finished, exit the sandbox if you are connected:

```console
$ exit
```

Then delete it:

```console
$ nemoclaw sandbox delete <name>
```

:::{note}
The NemoClaw Community repository accepts contributions. If you build a sandbox configuration that would be useful to others, you can submit it to the [NemoClaw-Community](https://github.com/NVIDIA/NemoClaw-Community) repository.
:::

## Next Steps

- {doc}`../sandboxes/community-sandboxes`: Full reference on community sandbox definitions, available images, and how to contribute your own
- {doc}`../safety-and-privacy/policies`: Understand the policy format and how to customize what a sandbox can do
- {doc}`../sandboxes/create-and-manage`: The isolation model and lifecycle behind every sandbox