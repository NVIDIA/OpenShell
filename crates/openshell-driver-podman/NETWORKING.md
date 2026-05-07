# Rootless Podman Networking

Deep-dive into how networking works in the Podman compute driver when running
rootless with pasta as the network backend. Covers the external tooling
(Podman, Netavark, pasta, aardvark-dns), the three nested namespace layers, and
the complete data paths for SSH, outbound traffic, and supervisor-to-gateway
communication.

For the general Podman driver architecture, lifecycle, API surface, and driver
comparison, see [README.md](README.md).

## Component Stack

Podman's networking is composed of four independent projects:

| Component | Language | Role |
|---|---|---|
| Podman | Go | Container runtime; orchestrates network lifecycle. |
| Netavark | Rust | Network backend; creates interfaces, bridges, firewall rules. |
| aardvark-dns | Rust | Authoritative DNS server for container name resolution. |
| pasta, part of passt | C | User-mode networking; L2-to-L4 socket translation for rootless containers. |

The key split: rootful containers default to Netavark bridge networking with
real kernel interfaces, while rootless containers commonly use pasta user-mode
networking without needing host privileges.

## How Netavark Works

Netavark is invoked by Podman as an external binary. It reads a JSON network
configuration from STDIN and executes one of three commands:

- `netavark setup <netns-path>` creates interfaces, assigns IPs, and sets up
  firewall rules for NAT and port-forwarding.
- `netavark teardown <netns-path>` reverses setup and removes interfaces and
  firewall rules.
- `netavark create` takes a partial network config and completes it by
  assigning subnets and gateways.

For rootful bridge networking:

1. Podman creates a network namespace for the container.
2. Podman invokes `netavark setup` with the network config JSON.
3. Netavark creates a bridge, such as `podman0`, if it does not exist. The
   default subnet is `10.88.0.0/16`.
4. Netavark creates a veth pair. One end goes into the container's netns and
   the other attaches to the bridge.
5. Netavark assigns an IP from the subnet to the container's veth interface.
6. Netavark configures iptables or nftables rules for masquerade and port
   mappings.
7. Netavark starts aardvark-dns when DNS is enabled, listening on the bridge
   gateway address.

```text
Host Kernel
  |
  +-- Bridge interface, such as "podman0"
  |     |
  |     +-- veth pair endpoint, host side, container 1
  |     +-- veth pair endpoint, host side, container 2
  |
  +-- Host physical interface, such as eth0
        |
        +-- NAT, iptables or nftables rules managed by Netavark
```

Netavark also supports macvlan networks, where the container gets a
sub-interface of a physical host NIC with its own MAC address, and external
plugins via a documented JSON API.

## How Pasta Works

Unprivileged users cannot create network interfaces on the host. They cannot
create veth pairs, bridges, or iptables rules. Netavark's bridge approach
cannot work directly for rootless containers without an additional rootless
networking layer.

Pasta, part of the `passt` project, operates in userspace and translates
between the container's L2 TAP interface and the host's L4 sockets. It requires
no capabilities or privileges.

```text
Container Network Namespace
  |
  +-- TAP device, such as "eth0"
  |     ^
  |     | L2 frames, Ethernet
  |     v
  +-- pasta process, userspace
        |
        | Translation: L2 frames <-> L4 sockets
        |
        v
  Host Network Stack, native TCP/UDP/ICMP sockets
```

For an outbound TCP connection from a container:

1. The application calls `connect()` to an external address.
2. The kernel routes the packet through the default gateway to the TAP device.
3. Pasta reads the raw Ethernet frame from the TAP file descriptor.
4. Pasta parses L2/L3/L4 headers and identifies the TCP SYN.
5. Pasta opens a native TCP socket on the host and calls `connect()` to the
   same destination.
6. When the host socket connects, pasta reflects the SYN-ACK back through the
   TAP as an L2 frame.
7. For ongoing data transfer, pasta translates between TAP frames and the host
   socket, coordinating TCP windows and acknowledgments between the two sides.

Pasta does not maintain per-connection packet buffers. It reflects observed
sending windows and ACKs directly between peers. This is a thinner translation
layer than a full TCP/IP stack.

### Built-in Services

Pasta includes minimal network services so the container stack can
auto-configure:

| Service | Purpose |
|---|---|
| ARP proxy | Resolves the gateway address to the host's MAC address. |
| DHCP server | Hands out a single IPv4 address, usually matching the host's upstream interface. |
| NDP proxy | Handles IPv6 neighbor discovery and SLAAC prefix advertisement. |
| DHCPv6 server | Hands out a single IPv6 address, usually matching the host's upstream interface. |

By default there is no NAT. Pasta copies the host's IP addresses into the
container namespace.

### Local Connection Bypass

For connections between the container and the host, pasta implements a local
bypass path:

- Packets with a local destination skip L2 translation.
- TCP uses `splice(2)`.
- UDP uses `recvmmsg(2)` and `sendmmsg(2)`.

### Port Forwarding

By default, pasta uses auto-detection. It scans `/proc/net/tcp` and
`/proc/net/tcp6` periodically and automatically forwards ports that are bound
and listening. Port forwarding is configurable through pasta options.

### Security Properties

Pasta is designed for rootless use:

- No dynamic memory allocation after startup.
- All capabilities dropped, except `CAP_NET_BIND_SERVICE` when granted.
- Restrictive seccomp profile.
- Detaches into its own user, mount, IPC, UTS, and PID namespaces.
- No external dependencies beyond libc.

### Inter-Container Limitation

Unlike bridge networking, pasta containers are isolated from each other by
default. No virtual bridge connects them. Communication requires port mappings
through the host, pods with a shared network namespace, or opting into rootless
Netavark bridge networking with `podman network create`.

## Three Nested Namespaces

The Podman compute driver creates three layers of network isolation:

```text
Namespace 1: Host
  |
  pasta manages port forwarding, such as 127.0.0.1:<ephemeral>
  gateway listens on its configured bind address and port
  |
Namespace 2: Rootless Podman network namespace, managed by pasta
  |
  Bridge "openshell", often 10.89.x.0/24
  aardvark-dns for container name resolution
  |
  Container netns
    supervisor, proxy, and relay client run here
    |
Namespace 3: Inner sandbox netns, created by supervisor
  |
  veth pair, such as 10.200.0.1 <-> 10.200.0.2
  iptables forces ordinary traffic through proxy
  user workload runs here
```

Pasta bridges namespace 1 and 2. The veth pair bridges namespace 2 and 3. The
proxy at the boundary of namespace 2 and 3 enforces network policy.

### Layer 1 Pasta

At driver startup, the driver ensures a Podman bridge network exists:

```rust
client.ensure_network(&config.network_name).await?;
```

This creates a bridge network named `openshell` by default, with DNS enabled.
In rootless mode, this bridge can exist inside a user namespace managed by
pasta. The bridge IP range is not reliably routable from the host.

```text
Host
  |
  127.0.0.1:<ephemeral>, pasta binds this on the host
  |
  pasta process, translates L4 sockets <-> L2 TAP frames
  |
  rootless network namespace
  |
  Bridge "openshell", such as 10.89.1.0/24
    |
    +-- 10.89.1.1, bridge gateway and aardvark-dns
    |
    +-- veth to container netns
         |
         10.89.1.2, container IP
```

### Layer 2 Container Networking

The container spec configures:

- `nsmode: "bridge"` to use the Podman bridge network.
- `networks` to attach to the configured bridge, `openshell` by default.
- `portmappings` with `host_port: 0`, `container_port: 2222`, and `protocol:
  "tcp"` to publish the SSH compatibility port on an ephemeral host port.
- `hostadd` entries for `host.containers.internal:host-gateway` and
  `host.openshell.internal:host-gateway`.

Pasta is not explicitly configured by the driver. The driver requests bridge
mode and logs the network backend that Podman reports at startup.

The `host.containers.internal` hostname is injected into `/etc/hosts` so the
supervisor can reach the gateway on the host. If `OPENSHELL_GRPC_ENDPOINT` is
empty, the driver auto-detects:

```rust
if config.grpc_endpoint.is_empty() {
    let scheme = if config.tls_enabled() {
        "https"
    } else {
        "http"
    };
    config.grpc_endpoint =
        format!("{scheme}://host.containers.internal:{}", config.gateway_port);
}
```

The bridge gateway IP is not a stable substitute in rootless mode because it
can live inside the user namespace rather than on the host.

### Layer 3 Inner Sandbox Network Namespace

Inside the container, the supervisor creates another network namespace for the
user workload:

```text
Container on the Podman bridge
  |
  Supervisor process, running in container's default netns
  |
  +-- Proxy listener at the inner namespace gateway address
  |
  +-- veth pair
  |
  +-- Inner network namespace
       |
       sandbox-side veth address
       |
       default route -> supervisor-side veth address
       |
       user code runs here
       |
       iptables rules:
         ACCEPT -> proxy TCP
         ACCEPT -> loopback
         ACCEPT -> established/related
         LOG    -> TCP SYN bypass attempts
         REJECT -> TCP
         LOG    -> UDP bypass attempts
         REJECT -> UDP
```

The supervisor uses `nsenter --net=` rather than `ip netns exec` to avoid sysfs
remount issues that arise under rootless Podman where real host
`CAP_SYS_ADMIN` is unavailable.

A tmpfs is mounted at `/run/netns` in the container spec so the supervisor can
create named network namespaces. In rootless Podman this directory does not
exist on the host, so a private tmpfs gives the supervisor its own writable
`/run/netns` without needing host filesystem access.

## Complete Data Paths

### SSH Session

```text
Client, openshell CLI
  |
  1. gRPC: CreateSshSession -> gateway, returns token and connect_path
  2. HTTP CONNECT /connect/ssh to gateway
     headers: x-sandbox-id, x-sandbox-token
  |
Gateway
  |
  3. Looks up SupervisorSession for sandbox_id
  4. Sends RelayOpen{channel_id} over ConnectSupervisor bidi stream
  |
  gRPC traverses host -> pasta translation -> container bridge
  |
Supervisor inside container
  |
  5. Receives RelayOpen, opens new RelayStream RPC back to gateway
  6. Sends RelayInit{channel_id} on the stream
  7. Connects to Unix socket /run/openshell/ssh.sock
  8. Bidirectional bridge: RelayStream <-> Unix socket
  |
SSH daemon inside container, Unix socket only
  |
  9. Authenticates. Access is gated by the relay chain.
  10. Spawns shell process
  11. Shell enters inner netns via setns(fd, CLONE_NEWNET)
  |
User shell in sandbox netns
```

The SSH daemon listens on a Unix socket with restrictive permissions. The
published TCP port mapping exists in the container spec for compatibility and
health/debug paths. Normal SSH communication uses the gRPC reverse-connect relay
pattern.

### Outbound HTTP Request

```text
User code in inner netns
  |
  1. curl https://api.example.com
     HTTP_PROXY points at the local sandbox proxy
  |
  2. TCP connect to proxy
     allowed by iptables as the only ordinary egress destination
  |
  3. HTTP CONNECT api.example.com:443
  |
Supervisor proxy in container netns
  |
  4. Policy evaluation with process identity
  5. SSRF check
  6. Optional L7 TLS intercept and HTTP method/path inspection
  |
  7. If allowed, TCP connect to api.example.com:443
     from the container netns
  |
  8. Through Podman bridge -> pasta -> host -> internet
```

### Supervisor gRPC Callback

The Podman driver auto-detects the callback endpoint scheme based on whether
TLS client certificates are configured. When the RPM's auto-generated PKI is in
place, the endpoint is `https://host.containers.internal:8080` and the
supervisor connects with mTLS. Without TLS configuration, it falls back to
`http://host.containers.internal:8080`.

```text
Supervisor in container netns
  |
  1. Connects to host.containers.internal:<port>
     with mTLS when OPENSHELL_TLS_* paths are set
  |
  2. Routed through container default gateway
  |
  3. Pasta translates L2 frame -> host L4 socket when rootless backend uses pasta
  |
  4. Host TCP socket connects to gateway
  |
Gateway
  |
  5. TLS handshake when enabled
  6. ConnectSupervisor bidirectional stream established
  7. Heartbeats at the interval accepted by the gateway
  8. Reconnects with exponential backoff on failure
  9. Same gRPC channel reused for RelayStream calls
```

The gateway binds to `0.0.0.0` by default in the RPM packaging. mTLS prevents
unauthenticated access even though the gateway is reachable from the network.
Client certificates are auto-generated by `init-pki.sh` on first start and
bind-mounted into sandbox containers by the Podman driver.

## Differences from the Kubernetes Driver

| Aspect | Kubernetes | Podman, rootless pasta |
|---|---|---|
| Container or pod IP | Routable cluster-wide | Non-routable from the host in common rootless setups. |
| Network reachability | Pod IPs reachable from gateway | Bridge not reliably routable from host; requires host aliases or published ports. |
| Sandbox to gateway | Direct TCP to Kubernetes service or endpoint | `host.containers.internal` through bridge and rootless backend. |
| SSH transport | Reverse gRPC relay | Reverse gRPC relay. |
| Port publishing | Not needed for relay | Ephemeral host port remains in the container spec for compatibility and debug paths. |
| TLS | mTLS via Kubernetes secrets | mTLS via mounted client files, RPM defaults, or explicit configuration. |
| DNS | Kubernetes CoreDNS | Podman bridge DNS through aardvark-dns when DNS is enabled. |
| Network policy | Kubernetes network policy for pod ingress plus supervisor policy | iptables inside inner sandbox netns plus supervisor policy. |
| Supervisor delivery | Kubernetes driver managed pod image or template | OCI image volume mount. |
| Secrets | Kubernetes Secret volume and env vars | Podman `secret_env` for handshake secret, plus mounted TLS files. |

Both drivers use the same reverse gRPC relay for SSH transport. The most
important Podman-specific difference is network reachability: in rootless
Podman, the bridge network is not reliably routable from the host, so
host-to-container and container-to-host communication must use host aliases,
published ports, or the supervisor relay.

## Port Assignments

| Port | Component | Purpose |
|---|---|---|
| `8080` | Gateway | gRPC and HTTP multiplexed default server port. |
| `2222` | Sandbox | Container port mapping default for the SSH compatibility port. |
| `3128` | Sandbox proxy | HTTP CONNECT proxy inside the sandbox network model. |
| `0` | Host | Ephemeral host port requested for the container SSH compatibility port. |

## Key Source Files

| File | What it controls |
|---|---|
| `crates/openshell-driver-podman/src/driver.rs` | Bridge network creation, gRPC endpoint auto-detection, rootless checks. |
| `crates/openshell-driver-podman/src/container.rs` | Container spec: network mode, port mappings, host aliases, tmpfs, capabilities. |
| `crates/openshell-driver-podman/src/client.rs` | Podman REST API calls for network ensure/inspect, port discovery, and events. |
| `crates/openshell-driver-podman/src/config.rs` | Network name, socket path, SSH port, gateway port defaults. |
| `crates/openshell-sandbox/src/sandbox/linux/netns.rs` | Inner network namespace, veth pair, IP addressing, iptables rules. |
| `crates/openshell-sandbox/src/proxy.rs` | HTTP CONNECT proxy, OPA policy, SSRF protection, L7 inspection. |
| `crates/openshell-sandbox/src/ssh.rs` | SSH daemon on Unix socket and shell process netns entry via `setns()`. |
| `crates/openshell-sandbox/src/supervisor_session.rs` | gRPC `ConnectSupervisor` stream and `RelayStream` for SSH tunneling. |
| `crates/openshell-sandbox/src/grpc_client.rs` | gRPC channel to gateway with mTLS or plaintext, keep-alive, and reconnect behavior. |
| `crates/openshell-server/src/ssh_tunnel.rs` | Gateway-side SSH tunnel, HTTP CONNECT endpoint, relay bridging. |
| `crates/openshell-server/src/supervisor_session.rs` | `SupervisorSessionRegistry`, relay claim/open lifecycle. |
| `crates/openshell-server/src/compute/mod.rs` | `ComputeRuntime::new_podman()` driver initialization. |
| `crates/openshell-core/src/config.rs` | Default constants for ports and network names. |
