# Bring Your Own Container

Run a sandbox with a custom container image. This lets you pre-install
languages, libraries, and tools so they're available in every sandbox session.

## Prerequisites

- A running navigator cluster (`nav cluster admin deploy`)
- Docker daemon running

## Quick start

Create a `Dockerfile` with the tools you need:

```dockerfile
FROM python:3.12-slim

# Install system tools useful for development
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl git iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Install Python libraries into the image so they're available in every sandbox
RUN pip install --no-cache-dir \
        numpy pandas requests

# Create a non-root user for the sandbox workload
RUN groupadd -g 1000 sandbox && \
    useradd -m -u 1000 -g sandbox sandbox

# Set up a working directory
WORKDIR /sandbox

CMD ["sleep", "infinity"]
```

Build and push it into the cluster:

```bash
nav sandbox image push --dockerfile Dockerfile --tag my-python:latest
```

Create a sandbox using the custom image:

```bash
nav sandbox create --image my-python:latest -- python -c "import numpy; print(numpy.__version__)"
```

Or start an interactive session:

```bash
nav sandbox create --image my-python:latest
```

## How it works

Navigator handles all the wiring automatically. You just build a standard
Linux container image with the tools you need -- no navigator-specific
dependencies or configuration required in your Dockerfile. When you create a
sandbox with `--image`, Navigator ensures that sandboxing (network policy,
filesystem isolation, SSH access) works the same as with the default image.

### Tips

- **Create a `sandbox` user** (uid/gid 1000) for better security. If your
  image doesn't have this user, the sandbox still works but runs the
  workload as root.
- **Install `iproute2`** for full network isolation. Without it the sandbox
  still enforces network policy but with reduced isolation.
- **Use a standard Linux base image** -- distroless and `FROM scratch` images
  are not supported.

TODO(#70): Remove this section once custom images are secure by default without requiring manual setup.

## Push flags

| Flag           | Description                                              |
| -------------- | -------------------------------------------------------- |
| `--dockerfile` | Path to the Dockerfile (required)                        |
| `--tag`        | Image name and tag (default: auto-generated)             |
| `--context`    | Build context directory (default: Dockerfile parent dir) |
| `--build-arg`  | Repeatable `KEY=VALUE` Docker build arguments            |

## Cleanup

Delete the sandbox when you're done:

```bash
nav sandbox delete <sandbox-name>
```
