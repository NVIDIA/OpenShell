# Rootless Podman Networking

Deep-dive into how networking works in the Podman compute driver when running rootless with pasta as the network backend. Covers the external tooling (Podman, Netavark, pasta, aardvark-dns), the three nested namespace layers, and the complete data paths for SSH, outbound traffic, and supervisor-to-gateway communication.

For the general Podman driver architecture (lifecycle, API surface, driver comparison), see [podman-driver.md](podman-driver.md).

## Component Stack

Podman's networking is composed of four independent projects:

| Component | Language | Role |
|-----------|----------|------|
| **Podman** | Go | Container runtime; orchestrates network lifecycle |
| **Netavark** | Rust | Network backend; creates interfaces, bridges, firewall rules |
| **aardvark-dns** | Rust | Authoritative DNS server for container name resolution (A/AAAA records) |
| **pasta** (part of passt) | C | User-mode networking; L2-to-L4 socket translation for rootless containers |

The key split: rootful containers default to Netavark (bridge networking with real kernel interfaces), while rootless containers default to pasta (user-mode networking, no privileges needed).

## How Netavark Works (Rootful)

Netavark is invoked by Podman as an external binary. It reads a JSON network configuration from STDIN and executes one of three commands:

- `netavark setup <netns-path>` -- creates interfaces, assigns IPs, sets up firewall rules for NAT/port-forwarding
- `netavark teardown <netns-path>` -- reverses setup; removes interfaces and firewall rules
- `netavark create` -- takes a partial network config and completes it (assigns subnets, gateways)

For rootful bridge networking:

1. Podman creates a network namespace for the container
2. Podman invokes `netavark setup` passing the network config JSON
3. Netavark creates a bridge (e.g., `podman0`) if it doesn't exist -- default subnet is `10.88.0.0/16`
4. Netavark creates a veth pair -- one end goes into the container's netns, the other attaches to the bridge
5. Netavark assigns an IP from the subnet to the container's veth interface (host-local IPAM)
6. Netavark configures iptables/nftables rules -- masquerade for outbound, DNAT for port mappings
7. Netavark starts aardvark-dns if DNS is enabled, listening on the bridge gateway address

```text
Host Kernel
  |
  +-- Bridge interface (e.g., "podman0")  <-- created by Netavark
  |     |
  |     +-- veth pair endpoint (host side, container 1)
  |     +-- veth pair endpoint (host side, container 2)
  |
  +-- Host physical interface (e.g., eth0)
        |
        +-- NAT (iptables/nftables rules managed by Netavark)
```

Netavark also supports macvlan networks (container gets a sub-interface of a physical host NIC with its own MAC, appearing directly on the physical network) and external plugins via a documented JSON API.

## How Pasta Works (Rootless)

### The Problem

Unprivileged users cannot create network interfaces on the host. They cannot create veth pairs, bridges, or configure iptables rules. Netavark's bridge approach cannot work directly for rootless containers.

### The Solution

Pasta (part of the `passt` project -- same binary, different command name) operates entirely in userspace, translating between the container's L2 TAP interface and the host's L4 sockets. It requires no capabilities or privileges.

```text
Container Network Namespace
  |
  +-- TAP device (e.g., "eth0")
  |     ^
  |     | L2 frames (Ethernet)
  |     v
  +-- pasta process (userspace)
        |
        | Translation: L2 frames <-> L4 sockets
        |
        v
  Host Network Stack (native TCP/UDP/ICMP sockets)
```

### Detailed Data Path

For an outbound TCP connection from a container:

1. The application calls `connect()` to an external address
2. The kernel routes the packet through the default gateway to the TAP device
3. Pasta reads the raw Ethernet frame from the TAP file descriptor
4. Pasta parses L2/L3/L4 headers and identifies the TCP SYN
5. Pasta opens a native TCP socket on the host and calls `connect()` to the same destination
6. When the host socket connects, pasta reflects the SYN-ACK back through the TAP as an L2 frame
7. For ongoing data transfer, pasta translates between TAP frames and the host socket, coordinating TCP windows and acknowledgments between the two sides

Pasta does NOT maintain per-connection packet buffers -- it reflects observed sending windows and ACKs directly between peers. This is a thinner translation layer than a full TCP/IP stack (like slirp4netns used).

### Built-in Services

Pasta includes minimalistic network services so the container's stack can auto-configure:

| Service | Purpose |
|---------|---------|
| ARP proxy | Resolves the gateway address to the host's MAC address |
| DHCP server | Hands out a single IPv4 address (same as host's upstream interface) |
| NDP proxy | Handles IPv6 neighbor discovery, SLAAC prefix advertisement |
| DHCPv6 server | Hands out a single IPv6 address (same as host's upstream interface) |

By default there is no NAT -- pasta copies the host's IP addresses into the container namespace.

### Local Connection Bypass (Splice Path)

For connections between the container and the host, pasta implements a zero-copy bypass:

- Packets with a local destination skip L2 translation entirely
- `splice(2)` for TCP (zero-copy), `recvmmsg(2)` / `sendmmsg(2)` for UDP (batched)
- Achieves ~38 Gbps TCP throughput for local connections

### Port Forwarding

By default, pasta uses auto-detection: it scans `/proc/net/tcp` and `/proc/net/tcp6` periodically and automatically forwards any ports that are bound/listening. Port forwarding is fully configurable via pasta options.

### Security Properties

- No dynamic memory allocation (`sbrk`, `brk`, `mmap` blocked via seccomp)
- All capabilities dropped (except `CAP_NET_BIND_SERVICE` if granted)
- Restrictive seccomp profiles (43 syscalls allowed on x86_64)
- Detaches into its own user, mount, IPC, UTS, PID namespaces
- No external dependencies beyond libc
- ~5,000 lines of code target

### Inter-Container Limitation

Unlike bridge networking, pasta containers are isolated from each other by default. No virtual bridge connects them. Communication requires port mappings through the host, pods (shared network namespace), or opting into rootless Netavark bridge networking via `podman network create`.

## Three Nested Namespaces in the Podman Driver

The Podman compute driver creates three layers of network isolation:

```text
Namespace 1: Host
  |
  pasta manages port forwarding (127.0.0.1:<ephemeral>)
  gateway listens on 0.0.0.0:8080
  |
Namespace 2: Rootless Podman network namespace (managed by pasta)
  |
  Bridge "openshell" (10.89.x.0/24)
  aardvark-dns for container name resolution
  |
  Container netns (10.89.x.2)
    supervisor, proxy, SSH daemon all run here
    |
Namespace 3: Inner sandbox netns (created by supervisor)
  |
  veth pair (10.200.0.1 <-> 10.200.0.2)
  iptables forces all traffic through proxy
  user workload runs here
```

Pasta bridges namespace 1 and 2, the veth pair bridges namespace 2 and 3, and the proxy at the boundary of 2/3 enforces network policy.

### Layer 1: Pasta (Rootless Podman Bridge)

At driver startup (`driver.rs:104-114`), the driver ensures a Podman bridge network exists:

```rust
client.ensure_network(&config.network_name).await?;
```

This creates a bridge network named `"openshell"` (default from `DEFAULT_NETWORK_NAME` in `openshell-core/src/config.rs`) with `dns_enabled: true`. In rootless mode, this bridge exists inside a user namespace managed by pasta. The bridge IP range (e.g., `10.89.x.x`) is not routable from the host.

```text
Host (your machine)
  |
  127.0.0.1:<ephemeral>  <--- pasta binds this on the host
  |
  [pasta process]  <--- translates L4 sockets <-> L2 TAP frames
  |
  [rootless network namespace]
  |
  Bridge "openshell" (10.89.1.0/24)
    |
    +-- 10.89.1.1 (bridge gateway, aardvark-dns listens here)
    |
    +-- veth --> Container netns
         |
         10.89.1.2 (container IP)
```

### Layer 2: Container Networking (Pasta Port Forwarding)

The container spec (`container.rs:447-471`) configures:

- `nsmode: "bridge"` -- uses the Podman bridge network
- `networks: {"openshell"}` -- attaches to the named bridge
- `portmappings: [{host_port: 0, container_port: 2222, protocol: "tcp"}]` -- publishes SSH on an ephemeral host port
- `hostadd: ["host.containers.internal:host-gateway"]` -- resolves to the host IP (pasta uses `169.254.1.2` in rootless mode)

Pasta is never explicitly configured. The driver sets `nsmode: "bridge"` and Podman selects pasta automatically as the rootless network backend. The driver logs the detected backend at startup (`driver.rs:86`):

```rust
network_backend = %info.host.network_backend,
```

The `host.containers.internal` hostname (the Podman equivalent of Docker's `host.docker.internal`) is injected into `/etc/hosts` so the supervisor can reach the gateway on the host. The gRPC callback endpoint is auto-detected at `driver.rs:116-130`:

```rust
if config.grpc_endpoint.is_empty() {
    config.grpc_endpoint =
        format!("http://host.containers.internal:{}", config.gateway_port);
}
```

The bridge gateway IP does NOT work for this purpose in rootless mode because it lives inside the user namespace, not on the host.

### Layer 3: Inner Sandbox Network Namespace

Inside the container, the supervisor creates another network namespace (`netns.rs:53-178`, setup at lines 53-63, `ip netns add` at line 77) for the user workload:

```text
Container (10.89.1.2 on the Podman bridge)
  |
  [Supervisor process - runs in container's default netns]
  |
  +-- Proxy listener at 10.200.0.1:3128
  |
  +-- veth pair: veth-h-{short_id} <-> veth-s-{short_id}
  |
  +-- Inner network namespace "sandbox-{short_id}"  (short_id = first 8 chars of UUID)
       |
       10.200.0.2/24
       |
       default route -> 10.200.0.1 (supervisor's proxy)
       |
       [User's code runs here]
       |
        iptables rules (IPv4; IPv6 installed best-effort):
          ACCEPT -> 10.200.0.1:{proxy_port} TCP (proxy)
          ACCEPT -> loopback (-o lo)
          ACCEPT -> established/related (conntrack)
          LOG    -> TCP SYN bypass attempts (rate-limited 5/sec)
          REJECT -> TCP (icmp-port-unreachable)
          LOG    -> UDP bypass attempts (rate-limited 5/sec)
          REJECT -> UDP (icmp-port-unreachable)
```

The supervisor uses `nsenter --net=` rather than `ip netns exec` to avoid sysfs remount issues that arise under rootless Podman where real `CAP_SYS_ADMIN` is unavailable (`netns.rs:681-716`, function body at 691).

A tmpfs is mounted at `/run/netns` in the container spec (`container.rs:458-463`) so the supervisor can create named network namespaces. In rootless Podman this directory does not exist on the host, so `mkdir` would fail with `EPERM` without a private tmpfs.

## Complete Data Paths

### SSH Session: Client to Sandbox Shell

```text
Client (CLI on user's machine)
  |
  1. gRPC: CreateSshSession -> gateway (returns token, connect_path)
  2. HTTP CONNECT /connect/ssh to gateway
     (headers: x-sandbox-id, x-sandbox-token)
  |
Gateway (host, port 8080)
  |
  3. Looks up SupervisorSession for sandbox_id
  4. Sends RelayOpen{channel_id} over ConnectSupervisor bidi stream
  |
  [gRPC traverses: host -> pasta L4 translation -> container bridge]
  |
Supervisor (inside container at 10.89.x.2)
  |
  5. Receives RelayOpen, opens new RelayStream RPC back to gateway
  6. Sends RelayInit{channel_id} on the stream
  7. Connects to Unix socket /run/openshell/ssh.sock
  8. Bidirectional bridge: RelayStream <-> Unix socket (16 KiB chunks)
  |
SSH daemon (inside container, Unix socket only, root-only permissions)
  |
  9. Authenticates (all auth accepted -- access gated by relay chain)
  10. Spawns shell process
  11. Shell enters inner netns via setns(fd, CLONE_NEWNET)
  |
User's shell (in sandbox netns at 10.200.0.2)
```

The SSH daemon listens on a Unix socket (not a TCP port) with 0600 permissions. The published port mapping (`host_port: 0 -> container_port: 2222`) exists in the container spec but is currently inert -- nothing listens on TCP 2222 inside the container. All SSH communication uses the gRPC reverse-connect relay pattern exclusively.

### Outbound HTTP Request from Sandbox Process

```text
User's code (inner netns, 10.200.0.2)
  |
  1. curl https://api.example.com
     (HTTP_PROXY=http://10.200.0.1:3128 set via environment)
  |
  2. TCP connect to 10.200.0.1:3128
     (allowed by iptables -- only permitted egress destination)
  |
  3. HTTP CONNECT api.example.com:443
  |
Supervisor proxy (10.200.0.1:3128 in container netns)
  |
  4. OPA policy evaluation (process identity via /proc/net/tcp -> PID)
  5. SSRF check (block internal IPs unless allowed by policy)
  6. Optional L7: TLS intercept, HTTP method/path inspection
  |
  7. If allowed: TCP connect to api.example.com:443
     (from container netns, 10.89.x.2)
  |
  8. Through Podman bridge -> pasta L2-to-L4 -> host -> internet
```

### Supervisor gRPC Callback to Gateway

The Podman driver auto-detects the callback endpoint scheme based on
whether TLS client certificates are configured. When the RPM's
auto-generated PKI is in place, the endpoint is
`https://host.containers.internal:8080` and the supervisor connects
with mTLS. Without TLS configuration, it falls back to
`http://host.containers.internal:8080`.

```text
Supervisor (container netns, 10.89.x.2)
  |
  1. mTLS connect to https://host.containers.internal:8080
     (resolves to 169.254.1.2:8080 via /etc/hosts)
     Client cert bind-mounted from host at /etc/openshell/tls/client/
  |
  2. Routed through container default gateway (bridge)
  |
  3. Pasta translates: L2 frame -> host L4 socket
  |
  4. Host TCP socket connects to gateway (0.0.0.0:8080)
  |
Gateway (host, 0.0.0.0:8080, mTLS enabled)
  |
  5. TLS handshake: server presents server cert, client presents client cert
  6. ConnectSupervisor bidirectional stream established
  7. Heartbeats every N seconds (gateway sends interval in SessionAccepted, default 15s)
  8. Reconnects with exponential backoff (1s initial, 30s max) on failure
  9. Same gRPC channel reused for RelayStream calls (no new TLS handshake)
```

The gateway binds to `0.0.0.0` by default in the RPM packaging. mTLS
prevents unauthenticated access even though the gateway is reachable
from the network. Client certificates are auto-generated by
`init-pki.sh` on first start and bind-mounted into sandbox containers
by the Podman driver. See `deploy/rpm/CONFIGURATION.md` for the full
configuration reference.

## Differences from the Kubernetes Driver

| Aspect | Kubernetes | Podman (rootless pasta) |
|--------|-----------|----------------------|
| Container/Pod IP | Routable cluster-wide | Non-routable (10.89.x.x inside user namespace) |
| Network reachability | Pod IPs reachable from gateway | Bridge not routable from host; requires `host.containers.internal` |
| Sandbox -> Gateway | Direct TCP to K8s service IP | `host.containers.internal` via bridge + pasta |
| SSH transport | Reverse gRPC relay (`ConnectSupervisor` + `RelayStream`) -- same mechanism as Podman | Reverse gRPC relay (`ConnectSupervisor` + `RelayStream`) |
| Port publishing | Not needed (routable IPs) | Ephemeral host port via pasta port forwarding |
| TLS | mTLS via K8s secrets | mTLS via auto-generated PKI (RPM default) or `--disable-tls` |
| DNS | Kubernetes CoreDNS | Podman bridge DNS (aardvark-dns, `dns_enabled: true`) |
| Network policy | K8s NetworkPolicy (ingress restricted to gateway) | iptables inside inner sandbox netns |
| Supervisor delivery | Kubernetes driver managed pod image/template | OCI image volume mount (FROM scratch image) |
| Secrets | K8s Secret volume mount (TLS certs); SSH handshake secret via env var | Podman `secret_env` API (hidden from `podman inspect`) |

Both drivers use the same reverse gRPC relay (`ConnectSupervisor` + `RelayStream`) for SSH transport. The most significant difference is network reachability: in rootless Podman, the bridge network is not routable from the host, so all communication between host and container goes through either pasta port forwarding (`portmappings`) or the `host.containers.internal` hostname (resolved to `169.254.1.2` by pasta).

## Port Assignments

| Port | Component | Purpose |
|------|-----------|---------|
| 8080 | Gateway | gRPC + HTTP multiplexed (default `DEFAULT_SERVER_PORT`) |
| 2222 | Sandbox | Port mapping in container spec (default `DEFAULT_SSH_PORT`); currently inert -- SSH daemon uses Unix socket only |
| 3128 | Sandbox proxy | HTTP CONNECT proxy (inside container, on inner netns host side) |
| 0 (ephemeral) | Host (via pasta) | Published mapping for container SSH port |

## Key Source Files

| File | What it controls |
|------|-----------------|
| `crates/openshell-driver-podman/src/driver.rs` | Bridge network creation, gRPC endpoint auto-detection, rootless checks |
| `crates/openshell-driver-podman/src/container.rs` | Container spec: network mode, port mappings, hostadd, tmpfs, capabilities |
| `crates/openshell-driver-podman/src/client.rs` | Podman REST API calls for network ensure/inspect, port discovery |
| `crates/openshell-driver-podman/src/config.rs` | Network name, socket path, SSH port, gateway port defaults |
| `crates/openshell-sandbox/src/sandbox/linux/netns.rs` | Inner network namespace: veth pair, IP addressing, iptables rules |
| `crates/openshell-sandbox/src/proxy.rs` | HTTP CONNECT proxy: OPA policy, SSRF protection, L7 inspection |
| `crates/openshell-sandbox/src/ssh.rs` | SSH daemon on Unix socket, shell process netns entry via `setns()` |
| `crates/openshell-sandbox/src/supervisor_session.rs` | gRPC ConnectSupervisor stream, RelayStream for SSH tunneling |
| `crates/openshell-sandbox/src/grpc_client.rs` | gRPC channel to gateway (mTLS or plaintext, keep-alive, adaptive windowing) |
| `crates/openshell-server/src/ssh_tunnel.rs` | Gateway-side SSH tunnel: HTTP CONNECT endpoint, relay bridging |
| `crates/openshell-server/src/supervisor_session.rs` | SupervisorSessionRegistry, relay claim/open lifecycle |
| `crates/openshell-server/src/compute/mod.rs` | `ComputeRuntime::new_podman()` -- Podman compute driver initialization |
| `crates/openshell-core/src/config.rs` | Default constants: ports, network name |
