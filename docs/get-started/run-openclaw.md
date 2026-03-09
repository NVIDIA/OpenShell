<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Run OpenClaw Safely

Launch a sandbox with OpenClaw from the [OpenShell Community catalog](https://github.com/NVIDIA/OpenShell-Community) using `--from openclaw`. The definition includes a container image, policy, and optional skills.

## Prerequisites

- **Docker** running. See {doc}`quickstart` for details.
- **OpenShell CLI** installed.
- **NVIDIA GPU** with [supported drivers](https://docs.nvidia.com/datacenter/tesla/drivers/) (required for OpenClaw).

## Create the Sandbox

```console
$ openshell sandbox create --from openclaw --keep
```

- `--from openclaw`: Fetches the OpenClaw definition from the community catalog, builds the image locally, and applies the bundled policy.
- `--keep`: Keeps the sandbox running after creation so you can connect and disconnect without recreating.

:::{note}
First build can take longer while Docker pulls base layers and installs dependencies. Later creates reuse the cached image.
:::

## Connect to the Sandbox

```console
$ openshell sandbox connect <name>
```

Use `<name>` from the creation output, or from `openshell sandbox list` if you did not pass `--name`.

## Explore the Environment

The image is pre-configured for OpenClaw: tools, runtimes, and policy are set. You can start working without policy changes.

## Inspect the Bundled Policy

To see what the sandbox is allowed to do:

```console
$ openshell policy get <name> --full
```

Review network policies (hosts, ports, binaries), filesystem policy, process restrictions, and inference rules. Saving to a file is useful for reference or customization:

```console
$ openshell policy get <name> --full > openclaw-policy.yaml
```

## Clean Up

Exit the sandbox (`exit`), then:

```console
$ openshell sandbox delete <name>
```

Use the sandbox name from `openshell sandbox list` or from `--name`.

:::{note}
To contribute a sandbox definition, see [OpenShell-Community](https://github.com/NVIDIA/OpenShell-Community).
:::

## Next Steps

- {doc}`../sandboxes/community-sandboxes`: Community definitions, images, and how to contribute.
- {doc}`../safety-and-privacy/policies`: Policy format and customization.
- {doc}`../sandboxes/create-and-manage`: Isolation model and lifecycle.
