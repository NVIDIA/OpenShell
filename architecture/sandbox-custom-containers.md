# Sandbox Custom Containers

Users can run `nemoclaw sandbox create --image <any-linux-image>` to launch a sandbox with an arbitrary container image while keeping the `navigator-sandbox` process supervisor in control.

## How It Works

When `--image` is provided and differs from the server's default sandbox image, the server activates **supervisor bootstrap mode**. The supervisor binary is side-loaded from the default sandbox image via a Kubernetes init container:

```mermaid
flowchart TB
    subgraph pod["Pod"]
        subgraph init["Init Container · copy-supervisor"]
            init_desc["Image: default sandbox image
            Copies /usr/local/bin/navigator-sandbox
            into shared emptyDir volume"]
        end

        init -- "emptyDir: navigator-supervisor-bin" --> agent

        subgraph agent["Agent Container"]
            agent_desc["Image: user-selected workload image
            Command: /opt/navigator/bin/navigator-sandbox
            Mounts shared volume read-only at /opt/navigator/bin/
            Env: NEMOCLAW_SANDBOX_ID, NEMOCLAW_ENDPOINT, ...
            Caps: SYS_ADMIN, NET_ADMIN, SYS_PTRACE"]
        end
    end
```

The server applies three transforms to the pod template (`sandbox/mod.rs`):

1. Adds an `emptyDir` volume named `navigator-supervisor-bin`.
2. Injects a `copy-supervisor` init container that uses the default sandbox image and runs `cp /usr/local/bin/navigator-sandbox /opt/navigator/bin/navigator-sandbox`.
3. Overrides the agent container's `command` to `/opt/navigator/bin/navigator-sandbox` and adds a read-only volume mount for the supervisor binary.

These transforms apply to both generated templates and user-provided `pod_template` overrides.

## CLI Usage

### Creating a sandbox with a custom image

```bash
nemoclaw sandbox create --image myimage:latest -- echo "hello from custom container"
```

When `--image` is set the CLI clears the default `run_as_user`/`run_as_group` policy (which expects a `sandbox` user) so that arbitrary images that lack that user can start without error.

### Pushing custom images into the cluster

```bash
nemoclaw sandbox image push --dockerfile ./Dockerfile --tag my-sandbox:latest
nemoclaw sandbox create --image my-sandbox:latest
```

`nemoclaw sandbox image push` accepts:

| Flag | Description |
|------|-------------|
| `--dockerfile` (required) | Path to the Dockerfile |
| `--tag` | Image name and tag (default: `navigator/sandbox-custom:<unix_timestamp>`) |
| `--context` | Build context directory (default: Dockerfile parent directory) |
| `--build-arg` | Repeatable `KEY=VALUE` Docker build arguments |

The command builds the image locally via the Docker daemon (respecting `.dockerignore`), then imports it into the cluster's containerd runtime using a `docker save` / `ctr -n k8s.io images import` pipeline — the same mechanism used for component images during bootstrap.

## Supervisor Behavior in Custom Images

The `navigator-sandbox` supervisor adapts to arbitrary environments:

- **Log file fallback**: Attempts to open `/var/log/navigator.log` for append; silently falls back to stdout-only logging if the path is not writable.
- **Command resolution**: Executes the command from CLI args, then the `NEMOCLAW_SANDBOX_COMMAND` env var (set to `sleep infinity` by the server), then `/bin/bash` as a last resort.
- **Network namespace**: Requires successful namespace creation for proxy isolation; startup fails in proxy mode if required capabilities (`CAP_NET_ADMIN`, `CAP_SYS_ADMIN`) or `iproute2` are unavailable.

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| Init container side-load | Avoids rebuilding every workload image with the supervisor binary baked in |
| `emptyDir` shared volume | Zero-config, no PVC needed, ephemeral by design |
| Read-only mount in agent | Supervisor binary cannot be tampered with by the workload |
| Command override | Ensures `navigator-sandbox` is the entrypoint regardless of the image's default CMD |
| Clear `run_as_user/group` for custom images | Prevents startup failure when the image lacks the default `sandbox` user |
| Non-fatal log file init | `/var/log/navigator.log` may be unwritable in arbitrary images; falls back to stdout |
| `docker save` / `ctr import` for push | Avoids requiring a registry for local dev; images land directly in the k3s containerd store |

## Limitations

- Distroless / `FROM scratch` images are not supported (the supervisor needs glibc, `/proc`, and a shell for the init container `cp`)
- Missing `iproute2` (or required capabilities) blocks startup in proxy mode because namespace isolation is mandatory
- The init container assumes the supervisor binary is at `/usr/local/bin/navigator-sandbox` in the default sandbox image
