# Bring Your Own Container

Run a sandbox with a custom container image. This example includes a
ready-to-use Python REST API that you can build, deploy, and reach from
your local machine through port forwarding.

## Prerequisites

- A running NemoClaw cluster (`ncl cluster admin deploy`)
- Docker daemon running

## What's in this example

| File         | Description                                             |
| ------------ | ------------------------------------------------------- |
| `Dockerfile` | Builds a Python 3.12 image that starts a REST API      |
| `app.py`     | Minimal HTTP server with `/hello` and `/health` routes  |

## Quick start (CLI)

### 1. Build and push the image

```bash
ncl sandbox image push \
    --dockerfile examples/bring-your-own-container/Dockerfile \
    --context    examples/bring-your-own-container \
    --tag        byoc-demo:latest
```

### 2. Create a sandbox with port forwarding

```bash
ncl sandbox create --image byoc-demo:latest --forward 8080
```

The `--forward 8080` flag opens an SSH tunnel so `localhost:8080` on your
machine reaches the REST API inside the sandbox.  Leave the trailing
`-- <command>` off so the image's own entrypoint (`python app.py`) runs.

### 3. Hit the API

```bash
curl http://localhost:8080/hello
# {"message": "hello from NemoClaw sandbox!"}

curl http://localhost:8080/hello/world
# {"message": "hello, world!"}

curl http://localhost:8080/health
# {"status": "ok"}
```

## Quick start (TUI — Gator)

### 1. Build and push the image

Same as step 1 above.

### 2. Launch Gator and create a sandbox

```bash
ncl gator
```

1. Press `2` to switch to the Sandboxes view.
2. Press `c` to open the Create Sandbox modal.
3. Fill in the fields:
   - **Image**: `byoc-demo:latest`
   - **Command**: clear this field (backspace the default) so the image
     entrypoint runs.
   - **Ports**: `8080`
4. Tab to **Create Sandbox** and press Enter.

Gator will create the sandbox, wait for it to become Ready, and
automatically start the port forward.  You'll see `fwd:8080` in the
NOTES column of the sandbox table.

### 3. Hit the API

Same `curl` commands as the CLI path — `localhost:8080` works from any
terminal on your machine.

## Running your own app

Replace `app.py` and the `Dockerfile` with your own application.  The
key requirements are:

- **Expose a port** and set it as the default `CMD` or `ENTRYPOINT`.
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

Port forwarding is entirely client-side: the CLI or TUI spawns a
background `ssh -L` tunnel through the gateway.  The sandbox's embedded
SSH daemon bridges the tunnel to `127.0.0.1:<port>` inside the
container.

## Push flags

| Flag           | Description                                              |
| -------------- | -------------------------------------------------------- |
| `--dockerfile` | Path to the Dockerfile (required)                        |
| `--tag`        | Image name and tag (default: auto-generated)             |
| `--context`    | Build context directory (default: Dockerfile parent dir) |
| `--build-arg`  | Repeatable `KEY=VALUE` Docker build arguments            |

## Cleanup

Delete the sandbox when you're done (this also stops port forwards):

```bash
ncl sandbox delete <sandbox-name>
```
