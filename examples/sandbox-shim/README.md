# sandbox-shim (experimental)

One small shim runs inside a Firecracker microVM or a gVisor (`runsc`)
sandbox. It serves the authenticated `IsolationBackend` and `SandboxProtocol`
contracts to the existing OpenShell supervisor and gateway on the host.

```text
gateway -> sandbox-shim driver -> supervisor -> Unix socket
   firecracker: driver relay -> Firecracker vsock -> shim (guest PID 1)
   gvisor:      runsc host UDS ----------------->  shim (sandbox PID 1)
```

This is a prototype. It does not use Landlock. On Firecracker it reuses the
production `openshell-sandbox` seccomp networking listener, `NetworkBroker`,
workload launcher, and binary pins through small public entry points those
crates add for it; the production boundary server does not use them.

## Layout inside the guest

The shim and the workload use separate root filesystems:

- **Shim root.** The shim runs from a root that contains only its own static
  binary and its control paths: launch credentials, the backend channel, and
  the CA source.
  - Firecracker: an initramfs, switched to a tmpfs at boot.
  - gVisor: a minimal OCI root.
- **Workload root.** The workload rootfs is a separate mount at
  `/run/openshell/workload`. Each nonprivileged process enters a new mount
  namespace and `pivot_root`s into that rootfs. Privileged processes join the
  holder's namespaces, which are already pivoted. Either way, shim paths do not
  exist in the workload's view.
- **CA material.** The shim writes CA files only in its own root. They are
  bind-mounted read-only at `/etc/openshell-tls`.
- **Control writes stay in shim-owned paths.** Launch credentials, the
  backend channel, and CA files are written only in the shim's root. In the
  workload rootfs, the only write is creating the `/etc/openshell-tls`
  mountpoint if the driver did not already create it. A process that is about
  to become the workload does this in its own new mount namespace:
  - nonprivileged: as guest root, before dropping to uid 10001;
  - privileged: as namespace root.
  For privileged workloads this happens once, while the shared namespace
  holder is set up.

## Privilege

The driver takes an explicit `--privilege`; there is no default.

| Setting | Workload runs as | Intended for |
|---|---|---|
| `nonprivileged` | guest uid/gid 10001, no supplementary groups, `no_new_privs`; workload rootfs owned by root | agents and harnesses such as Claude Code, with their subprocesses |
| `privileged` | root of one user, mount, and cgroup namespace shared by all its processes; namespace ids 0-65535 map to guest ids 100000-165535; workload rootfs owned by namespace root | nested containers, package installs, builds |

The OpenShell identity contract rejects uid 0, so `privileged` is not guest
init-namespace root. The reported identity is 100000, the guest id that
namespace root maps to. Namespace root owns its whole rootfs. The shim
delegates a cgroup v2 subtree to it (`openshell-workload/`, with processes in
its `init` leaf). Kernel modules, raw devices, and host-level networking are
unavailable.

## Network

The guest has no route out: Firecracker has no network device, and gVisor runs
with `--network=none`. Egress reaches the supervisor over the authenticated
backend channel.

### Firecracker: native mediation

Workloads use ordinary sockets and need no proxy settings. At startup the shim
qualifies seccomp user notification with `ADDFD`, then starts the
`openshell-sandbox` workload launcher with a networking-only listener and the
production `NetworkBroker`. Any failure stops the guest; there is no proxy
fallback. Every workload process (main, exec, PTY, and the privileged
namespace holder) is forked on the launcher thread, so it inherits the
listener, and installs a hardening filter just before exec.

- `socket`, `connect`, `bind`, `listen`, `sendto`, `sendmsg`, `sendmmsg`, and
  `setsockopt` notify the broker. It injects INET sockets created and bound to
  loopback in the shim's network namespace, and refuses other address
  families except Unix and netlink.
- An external TCP `connect` blocks until the supervisor decides. The shim
  answers `AcceptNetwork` with the destination, the broker's socket metadata,
  and the identity of the notifying thread, then relays bytes once the
  supervisor allows the open. A denial fails `connect` with `EACCES`.
- UDP and TCP DNS to `127.0.0.53:53` reach supervisor policy DNS over
  `Mediate` with the transport the workload used. The Firecracker image's
  `/etc/resolv.conf` names that relay. Other external UDP is refused.
- Loopback connections between workload processes stay local.
- The hardening filter refuses `io_uring`, `ptrace`, `process_vm_readv` and
  `process_vm_writev`, `pidfd_getfd`, `kcmp`, BPF, `perf_event_open`,
  `userfaultfd`, kernel modules, and nested seccomp listeners. Namespace,
  mount, and identity syscalls stay available for nested runtimes.
- Signals and file opens are not mediated. Their arguments are relative to the
  caller's namespaces, which nested containers do not share. Guest UID
  separation (nonprivileged) or the user namespace (privileged) keeps the
  workload from signalling or tracing the shim.
- If the broker or launcher stops, the shim ends the boundary.

Executable identity comes from the thread that made the syscall, resolved
through guest procfs by the shim, with per-generation trust-on-first-use digest
pins. A path is reported only if, resolved inside the process's own root, it
names the running executable. Processes whose root is not the workload rootfs,
such as nested containers, are reported as
`/.openshell/nested-root/<path in their root>`, so policy must name them
explicitly. A privileged workload owns its rootfs and can replace a binary
before first use; pins detect a replacement after that.

Use `policy-firecracker.yaml`, which grants HTTPS and plain HTTP, an IP-literal
grant, Docker Hub pulls for `dockerd`, and HTTP for BusyBox in nested
containers.

### gVisor: CONNECT proxy

gVisor does not provide seccomp user notification, so the shim listens on
`127.0.0.1:3128` as an HTTP `CONNECT` proxy and sets `HTTPS_PROXY`,
`HTTP_PROXY`, `ALL_PROXY`, and `NODE_USE_ENV_PROXY`. For each tunnel it finds
the client through guest `/proc/net/tcp` and `/proc/<pid>/fd`, hashes its
executable, resolves the host through supervisor policy DNS, and relays bytes
only after the supervisor allows the open. Other TCP, all UDP, and clients
that ignore the proxy variables have no route. Plain-HTTP proxy requests
receive `501`. This identity is best effort: the socket-owner lookup races
with exec and descriptor passing. Use `policy.yaml`.

A native backend for stock gVisor is a spike GO, but it is not built and the
shim does not use it. In that design, the shim traces `connect`
(`SECCOMP_RET_TRACE`) and substitutes a harmless `gettid` that carries a
private nonce. A SecCheck raw-event adapter in the supervisor returns the
original fd from the trusted Sentry event. Production gates and the earlier
NO-GO for reading the fd from registers or `SECCOMP_RET_DATA` are in
[validation/gvisor/README.md](validation/gvisor/README.md#current-recommendation-candidate-d).

## Policy

Attach rejects `landlock.compatibility: hard_requirement` and unrestricted
network mode. The supervisor adds baseline `filesystem_policy` paths to every
proxy-mode policy. As with Landlock `best_effort` on a kernel without Landlock,
the shim accepts those paths without enforcing them. It logs a warning and
states this in the `backend_audit` it returns on Confirm.

## Run

Prerequisites: Linux with `/dev/kvm` for Firecracker, Docker, and Rust.

| Variable | Contents |
|---|---|
| `SHIM_ROOTFS_DIR` | Extracted workload rootfs |
| `SHIM_FIRECRACKER` | `firecracker` binary |
| `SHIM_KERNEL` | Uncompressed kernel with initramfs, virtio-blk, vsock, ext4, user namespaces, and cgroup v2 support, such as a Firecracker CI `vmlinux` |
| `SHIM_RUNSC_DIR` | Directory containing `runsc` |

```shell
./run.sh firecracker nonprivileged   # or: gvisor, privileged
```

In another terminal:

```shell
export OPENSHELL_GATEWAY_ENDPOINT=http://127.0.0.1:18780
openshell sandbox create --name demo --no-tty --no-auto-providers \
  --policy policy-firecracker.yaml -- curl -sS https://example.com
```

On gVisor, use `--policy policy.yaml`.

```text
```

`run.sh` builds a static shim and hashes the rootfs content on every run. The
launch descriptor records the rootfs source digest, the ownership transform,
and the shim digest separately. The workload identity digest covers all three.
The shim refuses to start if its own binary does not match.

Docker is used only as a root helper; the script does not change host Docker or
network configuration.

- **Firecracker:** Docker builds the ext4 workload image with the right
  ownership. Firecracker itself runs as the invoking user, without the jailer.
- **gVisor:** Docker runs `runsc` in a `--network none` container labeled for
  this run only, with `--in-sandbox-cgroup=v2`. The workload runs inside
  `runsc`.

## Nested Docker in a privileged sandbox

```shell
mkdir -p /var/lib/docker && mount -t tmpfs tmpfs /var/lib/docker
unshare --net dockerd --iptables=false --ip6tables=false --bridge=none \
  --storage-driver=vfs &
docker pull alpine:3.21                     # Firecracker only
docker run --rm --network=host alpine:3.21 wget -qO- http://example.com
```

`dockerd` needs a network namespace owned by the workload's user namespace,
hence `unshare --net`. On Firecracker, `dockerd` and its containers inherit
the listener, so registry pulls and container egress are mediated like any
other connection, but the injected sockets live in the shim's network
namespace, not in the namespace that `dockerd` or a container creates.
Use `--network=host`. Bridge networking and published ports do not work, and
Docker network modes do not change where a container's sockets live.
`--network=none` or any other per-container network namespace is not an
egress boundary here: the container still receives sockets from the shim's
namespace, so it can reach anything policy allows by IP address. Hostname
lookups usually fail only because Docker drops the loopback nameserver from
the container's resolver configuration. Network policy is the only egress
control. On gVisor, load images offline (`docker load`); the
daemon has no network.

## End-to-end checks

```shell
./e2e.sh <firecracker|gvisor> <privileged|nonprivileged>
SHIM_E2E_DEV=1 ./e2e.sh ...   # with a development rootfs, see below
```

Each run starts a gateway, driver, and supervisor, then checks the following:

- Output, stderr, and exit code propagation.
- The kernel identifies the substrate.
- A shell subprocess tree runs.
- The privilege mode's identity:
  - `nonprivileged`: uid 10001, `NoNewPrivs`, and writes to `/usr` are denied.
  - `privileged`: namespace root with the 100000 mapping can mount tmpfs,
    chown, and create a top-level directory.
- **Networking on Firecracker:** no proxy variables are set; UDP and TCP
  DNS are answered by policy DNS; HTTPS and plain HTTP to the allowed host
  succeed; a granted IP literal succeeds and another is denied; a disallowed
  host and a disallowed binary (openssl) are denied; external UDP is refused;
  a loopback server in the workload is reachable. `sandbox exec`, with and
  without a PTY, is mediated and hardened.
- **Networking on gVisor:** curl reaches the allowed host through the proxy; a
  disallowed host and openssl are denied; direct DNS and direct IP fail.
- **Management paths.** The workload:
  - cannot see `/run/openshell` or the shim binary;
  - cannot read the shim's `/proc/<pid>/root` or `environ`;
  - cannot signal the shim;
  - cannot create files in the CA directory;
  - cannot modify the CA bundle, even after trying to remount its bind
    read-write in privileged mode. The files are owned by guest root, outside
    the namespace's id mapping;
  - on Firecracker, cannot use `io_uring`, `ptrace`, `process_vm_readv`,
    `pidfd_getfd`, or BPF.
- **Supervisor loss.** After `SIGKILL` on the supervisor:
  - the shim kills the workload, including the delegated cgroup in privileged
    mode;
  - the guest stops;
  - the host driver also stops the whole guest.
- **Development workloads** (`SHIM_E2E_DEV=1`):
  - a C program compiles with gcc and runs;
  - `claude --version` starts with no credentials;
  - in privileged mode, nested Docker loads the offline Alpine image and runs
    a container;
  - on Firecracker in privileged mode, `dockerd` pulls `alpine:3.21` online,
    and a `--network=host` container reaches an allowed host and is denied a
    destination granted only to curl.

The development rootfs used for testing was `buildpack-deps:26.04` with Docker
29.2.1 static binaries and the Claude Code binary in `/usr/local/bin`, plus
`/opt/offline-images/alpine-3.22.tar`. It contains no credentials.

## Limits

- The driver manages one sandbox at a time. Resource requests, environment and
  template overrides, provider files, suspend/resume, and supervisor takeover
  or recovery are unsupported. Losing the supervisor ends the workload.
- The workload shares the guest PID namespace, so it can see shim processes but
  not signal or trace them.
- No per-path enforcement of authored `filesystem_policy`: best-effort paths
  are accepted and reported unenforced. No Landlock is applied. On gVisor no
  seccomp filter is applied either.
  Separating the workload rootfs, mounting CA read-only, and file ownership
  protect only the shim's control paths. Nothing inside the guest resists guest
  init-namespace root; the outer boundary is the VM or the gVisor sandbox.
- On Firecracker, the outer fence (no network device) remains the backstop for
  the seccomp `CONTINUE` race on DNS sends that the production broker
  documents. Debuggers that need `ptrace` and runtimes that need `io_uring` or
  BPF do not work.
- Resize and loopback port forwarding are implemented but not covered by
  `e2e.sh`, nor is exec on gVisor. Kernel builds are not tested.
- Tested on aarch64 with Firecracker v1.18.0, the Firecracker CI 6.1 kernel,
  and gVisor release-20261109.0 (systrap).
