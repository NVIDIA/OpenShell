<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Custom Containers

Build a custom container image and run it as a NemoClaw sandbox.

## Prerequisites

- NemoClaw CLI installed (`pip install nemoclaw`)
- Docker running on your machine
- A Dockerfile for your workload

## Step 1: Create a Sandbox from Your Dockerfile

Point `--from` at the directory containing your Dockerfile:

```console
$ nemoclaw sandbox create --from ./my-app --keep --name my-app
```

The CLI builds the image locally via Docker, pushes it into the cluster, and
creates the sandbox --- all in one step. No external container registry is
needed.

You can also pass a full container image reference if the image is already
built:

```console
$ nemoclaw sandbox create --from my-registry.example.com/my-image:latest --keep --name my-app
```

## Step 2: Forward Ports

If your container runs a service, forward the port to your host:

```console
$ nemoclaw sandbox forward start 8080 my-app -d
```

The `-d` flag runs the forward in the background so you can continue using
your terminal.

## Step 3: Iterate

When you change your Dockerfile, delete the sandbox and recreate:

```console
$ nemoclaw sandbox delete my-app && \
    nemoclaw sandbox create --from ./my-app --keep --name my-app
```

## Shortcut: Create with Forwarding and a Startup Command

You can combine port forwarding and a startup command in a single step:

```console
$ nemoclaw sandbox create --from ./my-app --forward 8080 --keep -- ./start-server.sh
```

This creates the sandbox, sets up port forwarding on port 8080, and runs
`./start-server.sh` as the sandbox command.

:::{warning}
Distroless and `FROM scratch` images are not supported. The NemoClaw
supervisor requires glibc, `/proc`, and a shell to operate. Images missing
`iproute2` or required Linux capabilities will fail to start in proxy mode.
Ensure your base image includes these dependencies.
:::

## Next Steps

- {doc}`create-and-manage` --- full sandbox lifecycle commands
- {doc}`providers` --- attach credentials to your custom container
- {doc}`/safety-and-privacy/policies` --- write a policy tailored to your workload
- {doc}`/safety-and-privacy/security-model` --- understand the isolation layers applied to custom images