# Sandbox Custom Containers

Users can run `openshell sandbox create --from <source>` to launch a sandbox with a custom container image while keeping the `openshell-sandbox` process supervisor in control.

## The `--from` Flag

The `--from` flag accepts four kinds of input:

| Input | Example | Behavior |
|-------|---------|----------|
| **Community sandbox name** | `--from openclaw` | Resolves to `ghcr.io/nvidia/openshell-community/sandboxes/openclaw:latest` |
| **Dockerfile path** | `--from ./Dockerfile` | Builds the image into the host Docker daemon, then creates the sandbox |
| **Directory with Dockerfile** | `--from ./my-sandbox/` | Uses the directory as the build context |
| **Full image reference** | `--from myregistry.com/img:tag` | Uses the image directly |

### Resolution heuristic

The CLI classifies the value in this order:

1. **Existing file** whose name contains "Dockerfile" (case-insensitive) — treated as a Dockerfile to build.
2. **Existing directory** containing a `Dockerfile` — treated as a build context directory.
3. **Missing explicit local path** (for example `./Dockerfile`, `../ctx`, or an absolute path) — rejected locally instead of sent to the gateway as an image pull.
4. **Contains `/`, `:`, or `.`** — treated as a full container image reference.
5. **Otherwise** — treated as a community sandbox name, expanded to `{OPENSHELL_COMMUNITY_REGISTRY}/{name}:latest`.

The community registry prefix defaults to `ghcr.io/nvidia/openshell-community/sandboxes` and can be overridden with the `OPENSHELL_COMMUNITY_REGISTRY` environment variable.

### GPU image-name detection

`sandbox create` also infers GPU intent from the final image name. The current rule matches when the last image name component contains `gpu` (for example `ghcr.io/nvidia/openshell-community/sandboxes/nvidia-gpu:latest` or `registry.example.com/team/my-gpu-image:latest`). When that rule matches, the sandbox request is treated the same as passing `--gpu`.

### Dockerfile build flow

When `--from` points to a Dockerfile or directory, the CLI:

1. Builds the image locally via the Docker daemon (respecting `.dockerignore`).
2. Creates the sandbox with the resulting local image tag.

The build step aborts with a clear error if the Docker build stream stays silent for longer than `OPENSHELL_BUILD_NO_PROGRESS_TIMEOUT_SECS` seconds (default 1800). This is a guard against deadlocked container runtimes — most commonly an under-provisioned VM (e.g. macOS Colima with the default 2 vCPU / 2 GiB) where BuildKit can stop emitting events partway through a multi-step build and never recover. Raise the value if a legitimate build step is just quiet, or lower it for tighter CI budgets.

## How It Works

The supervisor binary (`openshell-sandbox`) is **always side-loaded** from the k3s node filesystem via a read-only `hostPath` volume. It is never baked into sandbox images. This applies to all sandbox pods — whether using the default community base image, a custom image, or a user-built Dockerfile.

```mermaid
flowchart TB
    subgraph node["K3s Node"]
        bin["/opt/openshell/bin/openshell-sandbox
        (built into cluster image, updatable via docker cp)"]
    end

    node -- "hostPath (readOnly)" --> agent

    subgraph pod["Pod"]
        subgraph agent["Agent Container"]
            agent_desc["Image: community base or custom image
            Command: /opt/openshell/bin/openshell-sandbox
            Volume: /opt/openshell/bin (ro hostPath)
            Env: OPENSHELL_SANDBOX_ID, OPENSHELL_ENDPOINT, ...
            Caps: SYS_ADMIN, NET_ADMIN, SYS_PTRACE"]
        end
    end
```

The server applies these transforms to every sandbox pod template (`sandbox/mod.rs`):

1. Adds a `hostPath` volume named `openshell-supervisor-bin` pointing to `/opt/openshell/bin` on the node.
2. Mounts it read-only at `/opt/openshell/bin` in the agent container.
3. Overrides the agent container's `command` to `/opt/openshell/bin/openshell-sandbox`.
4. Sets `runAsUser: 0` so the supervisor has root privileges for namespace creation, proxy setup, and Landlock/seccomp.

These transforms apply to every generated pod template.

## CLI Usage

### Creating a sandbox from a community image

```bash
openshell sandbox create --from openclaw
```

### Creating a sandbox with a custom image

```bash
openshell sandbox create --from myimage:latest -- echo "hello from custom container"
```

When `--from` is set the CLI clears the default `run_as_user`/`run_as_group` policy (which expects a `sandbox` user) so that arbitrary images that lack that user can start without error.

### Building from a Dockerfile in one step

```bash
openshell sandbox create --from ./Dockerfile -- echo "built and running"
openshell sandbox create --from ./my-sandbox/  # directory with Dockerfile
```

## Supervisor Behavior in Custom Images

The `openshell-sandbox` supervisor adapts to arbitrary environments:

- **Log file fallback**: Attempts to open `/var/log/openshell.log` for append; if the path is not writable, the supervisor keeps console shorthand logging on stderr only.
- **Command resolution**: Executes the command from CLI args, then the `OPENSHELL_SANDBOX_COMMAND` env var (set to `sleep infinity` by the server), then `/bin/bash` as a last resort.
- **Startup seccomp prelude**: Before parsing CLI args or starting the async runtime, the supervisor sets `PR_SET_NO_NEW_PRIVS` and installs a narrow seccomp filter that blocks mount/remount, the new mount API syscalls, module loading, kexec, `bpf`, `perf_event_open`, and `userfaultfd`. This closes the privileged remount window while still leaving required child-setup syscalls such as `setns` available.
- **Network namespace**: Requires successful namespace creation for proxy isolation; startup fails in proxy mode if required capabilities (`CAP_NET_ADMIN`, `CAP_SYS_ADMIN`) or `iproute2` are unavailable. If the `iptables` package is present, the supervisor installs OUTPUT chain rules (LOG + REJECT) inside the namespace to provide fast-fail behavior (immediate `ECONNREFUSED` instead of a 30-second timeout) and diagnostic logging when processes attempt direct connections that bypass the HTTP CONNECT proxy. If `iptables` is absent, the supervisor logs a warning and continues — core network isolation still works via routing.

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| Unified `--from` flag | Single entry point for community names, Dockerfiles, directories, and image refs — removes the need to know registry paths |
| Community name resolution | Bare names like `openclaw` expand to the GHCR community registry, making the common case simple |
| Auto build for Dockerfiles | Eliminates the two-step `docker build` + `create` workflow for local Docker-backed development |
| `OPENSHELL_COMMUNITY_REGISTRY` env var | Allows organizations to host their own community sandbox registry |
| hostPath side-load | Supervisor binary lives on the node filesystem — no init container, no emptyDir, no extra image pull. Faster pod startup. |
| Read-only mount in agent | The supervisor binary is mounted read-only, and the startup seccomp prelude blocks the remount syscalls that would otherwise reopen it for writes once privileged bootstrap has completed. |
| Command override | Ensures `openshell-sandbox` is the entrypoint regardless of the image's default CMD |
| Clear `run_as_user/group` for custom images | Prevents startup failure when the image lacks the default `sandbox` user |
| Non-fatal log file init | `/var/log/openshell.log` may be unwritable in arbitrary images; falls back to stdout |
| Host Docker image store | Dockerfile sources build into the host Docker daemon and are referenced by local image tag. |
| Optional `iptables` for bypass detection | Core network isolation works via routing alone (`iproute2`); `iptables` only adds fast-fail (`ECONNREFUSED`) and diagnostic LOG entries. Making it optional avoids hard failures in minimal images that lack `iptables` while giving better UX when it is available. |

## Limitations

- Distroless / `FROM scratch` images are not supported (the supervisor needs glibc and `/proc`)
- Missing `iproute2` (or required capabilities) blocks startup in proxy mode because namespace isolation is mandatory
- Kubernetes gateways require images to be available to the cluster runtime. Dockerfile sources build into the host Docker daemon only; use a registry image reference when the selected gateway cannot access the host Docker image store.
