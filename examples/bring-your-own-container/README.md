# Bring Your Own Container

Run a sandbox with a custom container image. This example includes a
ready-to-use Python REST API that you can build, deploy, and reach from
your local machine through port forwarding.

## Prerequisites

- A running NemoClaw cluster (`nemoclaw cluster admin deploy`)
- Docker daemon running

## What's in this example

| File         | Description                                             |
| ------------ | ------------------------------------------------------- |
| `Dockerfile` | Builds a Python 3.12 image that starts a REST API      |
| `app.py`     | Minimal HTTP server with `/hello` and `/health` routes  |

## Quick start

### 1. Build and push the image

```bash
nemoclaw sandbox image push \
    --dockerfile examples/bring-your-own-container/Dockerfile \
    --tag        byoc-demo:latest
```

### 2. Create a sandbox with port forwarding

```bash
nemoclaw sandbox create --image byoc-demo:latest --forward 8080 -- python /sandbox/app.py
```

The `--forward 8080` flag opens an SSH tunnel so `localhost:8080` on your
machine reaches the REST API inside the sandbox.

**Important:** The image's `CMD` / `ENTRYPOINT` does not run automatically.
NemoClaw replaces it with the sandbox supervisor (which manages SSH access,
network policy, etc.).  You must pass your application's start command
after `--` so it is executed via SSH once the sandbox is ready.

### 3. Hit the API

```bash
curl http://localhost:8080/hello
# {"message": "hello from NemoClaw sandbox!"}

curl http://localhost:8080/hello/world
# {"message": "hello, world!"}

curl http://localhost:8080/health
# {"status": "ok"}
```

## Running your own app

Replace `app.py` and the `Dockerfile` with your own application.  The
key requirements are:

- **Pass your start command explicitly** — use `-- <command>` on the CLI.
  The image's `CMD` / `ENTRYPOINT` is replaced by the sandbox supervisor
  at runtime.
- **Create a `sandbox` user** (uid/gid 1000) for non-root execution.
- **Install `iproute2`** for full network namespace isolation.
- **Use a standard Linux base image** — distroless and `FROM scratch`
  images are not supported.

TODO(#70): Remove the sandbox user note once custom images are secure by default without requiring manual setup.

## How it works

NemoClaw handles all the wiring automatically.  You build a standard
Linux container image — no NemoClaw-specific dependencies or
configuration required.  When you create a sandbox with `--image`,
NemoClaw ensures that sandboxing (network policy, filesystem isolation,
SSH access) works the same as with the default image.

Port forwarding is entirely client-side: the CLI spawns a background
`ssh -L` tunnel through the gateway.  The sandbox's embedded SSH daemon
bridges the tunnel to `127.0.0.1:<port>` inside the container.

## Push flags

| Flag           | Description                                              |
| -------------- | -------------------------------------------------------- |
| `--dockerfile` | Path to the Dockerfile (required)                        |
| `--tag`        | Image name and tag (default: auto-generated)             |
| `--context`    | Docker build context directory for COPY/ADD (default: Dockerfile parent dir) |
| `--build-arg`  | Repeatable `KEY=VALUE` Docker build arguments            |

## Cleanup

Delete the sandbox when you're done (this also stops port forwards):

```bash
nemoclaw sandbox delete <sandbox-name>
```
