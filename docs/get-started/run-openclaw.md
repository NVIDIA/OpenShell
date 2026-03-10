<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Run OpenClaw Safely

This tutorial shows you how to launch a sandbox with OpenClaw from the [OpenShell Community catalog](https://github.com/NVIDIA/OpenShell-Community) using the `--from` flag. This is a pre-built sandbox configuration that includes a container image, a tailored policy, and optional skills.

## What You Will Learn

- Understand what community sandboxes are and how they differ from default sandboxes.
- Use the `--from` flag to pull and build a complete sandbox configuration.
- Inspect the bundled policy that ships with a community sandbox.

## Prerequisites

- Met the prerequisites and installed the OpenShell CLI as described in the {doc}`quickstart` guide.
- NVIDIA GPU with drivers installed. OpenClaw requires GPU acceleration.<!--Need to specify the NVIDIA GPU driver version or add reference link-->

## Create the Sandbox

Run the following command:

```console
$ openshell sandbox create --from openclaw --keep
```

The `--from` flag tells the CLI to pull a sandbox definition from the OpenShell Community catalog. Here is what happens behind the scenes:

1. Fetches the definition. The CLI downloads the OpenClaw sandbox definition from the OpenShell-Community repository. This includes a Dockerfile, a policy YAML, and any bundled skills.
2. Builds the image. The CLI builds the Dockerfile locally using Docker. The resulting image includes all tools and dependencies that OpenClaw needs.
3. Applies the bundled policy. Instead of the generic default policy, the sandbox starts with a policy written specifically for the OpenClaw workload. It allows the endpoints and binaries that OpenClaw requires.
4. Creates and keeps the sandbox. The `--keep` flag ensures the sandbox stays running after creation so you can connect and disconnect freely.

:::{note}
The first build takes longer because Docker needs to pull base layers and install dependencies. Subsequent creates reuse the cached image.
:::

## Connect to the Sandbox

After creation completes, connect to the running sandbox:

```console
$ openshell sandbox connect <name>
```

Replace `<name>` with the sandbox name shown in the creation output. If you did not specify a name with `--name`, the CLI assigns one automatically. Run `openshell sandbox list` to find it.

## Explore the Environment

The sandbox comes pre-configured for the OpenClaw workload. The tools, runtimes, and libraries that OpenClaw needs are already installed in the container image. The policy is tuned to allow the specific network endpoints and operations that OpenClaw uses, so you can start working immediately without policy adjustments.

## Inspect the Bundled Policy

To see exactly what the sandbox is allowed to do, pull the full policy:

```console
$ openshell policy get <sandbox-name> --full
```

This outputs the complete policy YAML. Review it to understand the sandbox's permissions:

- Network policies, which hosts and ports the sandbox can reach, and which binaries are allowed to initiate those connections.
- Filesystem policy, which paths are read-only and which are read-write.
- Process restrictions, which user and group the sandbox runs as.
- Inference rules, which inference routing hints are allowed.

Reviewing the bundled policy is a good practice before you use a community sandbox for sensitive work.

:::{tip}
Save the policy to a file for reference or as a starting point for customization:

```console
$ openshell policy get <name> --full > openclaw-policy.yaml
```
:::

## Clean Up

Exit the sandbox if you are connected:

```console
$ exit
```

Delete the sandbox:

```console
$ openshell sandbox delete <name>
```

:::{note}
The OpenShell Community repository accepts contributions. If you build a sandbox configuration that would be useful to others, submit it to the [OpenShell-Community](https://github.com/NVIDIA/OpenShell-Community) repository.
:::

## Next Steps

- {doc}`../sandboxes/community-sandboxes`: Full reference on community sandbox definitions, available images, and how to contribute your own.
- {doc}`../safety-and-privacy/policies`: Learn the policy format and how to customize what a sandbox can do.
- {doc}`../sandboxes/create-and-manage`: Understand the isolation model and lifecycle behind every sandbox.
