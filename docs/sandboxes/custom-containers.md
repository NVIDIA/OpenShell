<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Custom Containers

You can run any Linux container image as a sandbox while keeping the NemoClaw supervisor in control of security enforcement.

## How It Works

When you specify `--image`, the server activates supervisor bootstrap mode. The `navigator-sandbox` supervisor binary is side-loaded from the default sandbox image via a Kubernetes init container, then mounted read-only into your custom container. This means you do not need to build the supervisor into your image.

```{mermaid}
flowchart TB
    subgraph pod["Pod"]
        subgraph init["Init Container · copy-supervisor"]
            init_desc["Image: default sandbox image\nCopies navigator-sandbox binary\ninto shared volume"]
        end

        init -- "shared volume" --> agent

        subgraph agent["Agent Container"]
            agent_desc["Image: your custom image\nRuns navigator-sandbox as entrypoint\nFull sandbox policy enforcement"]
        end
    end
```

## Building and Pushing Images

Build a custom container image and import it into the cluster:

```console
$ nemoclaw sandbox image push \
  --dockerfile ./Dockerfile \
  --tag my-app:latest \
  --context .
```

The image is built locally via Docker and imported directly into the cluster's containerd runtime. No external registry is needed.

| Flag | Description |
|------|-------------|
| `--dockerfile` (required) | Path to the Dockerfile. |
| `--tag` | Image name and tag (default: auto-generated timestamp). |
| `--context` | Build context directory (default: Dockerfile parent). |
| `--build-arg KEY=VALUE` | Docker build argument (repeatable). |

## Creating a Sandbox with a Custom Image

```console
$ nemoclaw sandbox create --image my-app:latest --keep --name my-app
```

When `--image` is set, the CLI clears the default `run_as_user`/`run_as_group` policy, since custom images may not have the default `sandbox` user.

### With Port Forwarding

If your container runs a service:

```console
$ nemoclaw sandbox create --image my-app:latest --forward 8080 --keep -- ./start-server.sh
```

The `--forward` flag starts a background port forward before the command runs, so the service is reachable at `localhost:8080` immediately.

## Updating a Custom Image

To iterate on your container:

```console
$ nemoclaw sandbox delete my-app
$ nemoclaw sandbox image push --dockerfile ./Dockerfile --tag my-app:v2
$ nemoclaw sandbox create --image my-app:v2 --keep --name my-app
```

## Limitations

- **Distroless / `FROM scratch` images are not supported.** The supervisor needs glibc, `/proc`, and a shell.
- **Missing `iproute2` blocks proxy mode.** Network namespace isolation requires `iproute2` and the `CAP_NET_ADMIN`/`CAP_SYS_ADMIN` capabilities.
- The init container assumes the supervisor binary is at a fixed path in the default sandbox image.
