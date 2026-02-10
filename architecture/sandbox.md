# Sandbox Architecture

Navigator's sandboxing isolates a user command in a child process while policy parsing and
platform-specific enforcement live behind clear interfaces. The `navigator-sandbox` binary is the
entry point and spawns a child process, applying restrictions before `exec`.

## Components

- `crates/navigator-sandbox`: CLI + library that loads policy, spawns the child process, and applies sandbox rules.
- `crates/navigator-core`: shared types and utilities (policy schema, errors, config).
- `crates/navigator-server`: Server that stores sandbox policies and serves them via gRPC.

## Policy Model

Sandboxing is driven by a required policy configuration. There are two ways to provide it:

1. **gRPC mode** (production): Set `NAVIGATOR_SANDBOX_ID` and `NAVIGATOR_ENDPOINT` environment
   variables. The sandbox will fetch its policy from the Navigator server at startup via the
   `GetSandboxPolicy` RPC.

2. **File mode** (local development): Provide a YAML policy file via `--policy` or
   `NAVIGATOR_SANDBOX_POLICY`.

The policy schema includes:

- `filesystem`: read-only and read-write allow lists, plus optional inclusion of the workdir. Any directories under `read_write` will automatically be created if they do not exist.
- `network`: mode (`allow`, `block`, `proxy`) and optional proxy configuration.
- `landlock`: compatibility behavior (`best_effort` or `hard_requirement`).
- `process`: optional `run_as_user`/`run_as_group` to drop privileges for the child process.

See `docs/sandbox-policy.yaml` for an example policy.

## Dynamic Policy Loading (gRPC Mode)

When running in Kubernetes, the sandbox fetches its policy dynamically from the Navigator server
via gRPC instead of reading from a local file. This is the preferred mode for production deployments.

### Environment Variables

The pod template automatically injects these environment variables:

- `NAVIGATOR_SANDBOX_ID`: The sandbox entity ID in Navigator's store
- `NAVIGATOR_ENDPOINT`: gRPC endpoint for the Navigator server (e.g., `http://navigator:8080`)
- `NAVIGATOR_SANDBOX_COMMAND`: The command to execute inside the sandbox (user-provided, defaults to `/bin/bash` if not set)

### Startup Flow

1. Pod starts with `navigator-sandbox` entrypoint
2. Sandbox binary reads `NAVIGATOR_SANDBOX_ID` and `NAVIGATOR_ENDPOINT` from environment
3. Calls `GetSandboxPolicy(sandbox_id)` gRPC to fetch policy from Navigator server
4. Applies sandbox restrictions (Landlock, seccomp, privilege drop)
5. Executes the command from `NAVIGATOR_SANDBOX_COMMAND`, CLI args, or `/bin/bash` by default

### Policy Storage

The sandbox policy is stored as part of the `SandboxSpec` protobuf message in Navigator's persistence
layer. The policy is required when creating a sandbox via the `CreateSandbox` gRPC call. The policy
definition lives in `proto/sandbox.proto`.

## Linux Enforcement (Landlock + Seccomp)

Linux enforcement lives in `crates/navigator-sandbox/src/sandbox/linux`.

- Landlock restricts filesystem access to the allow lists from the policy. If no paths are listed,
  Landlock is skipped. When enabled, a ruleset is created and enforced before the child `exec`.
- Seccomp blocks socket creation for common network domains (IPv4/IPv6 and others), preventing the
  child process from opening outbound sockets directly.

## Proxy Routing

When `network.mode: proxy` is set, network traffic is forced through an HTTP CONNECT proxy that
enforces the `allow_hosts` allowlist. The proxy implementation lives in
`crates/navigator-sandbox/src/proxy.rs`.

### Network Namespace Isolation (Linux)

Seccomp alone cannot fully enforce proxy-only networking because it cannot filter `connect()` calls
by destination address (the sockaddr struct is a userspace pointer that seccomp cannot dereference).
A process that ignores `HTTP_PROXY` environment variables could connect directly to any IP.

To close this gap, proxy mode uses Linux network namespaces to isolate the sandboxed process:

```
HOST NAMESPACE                          SANDBOX NAMESPACE
──────────────                          ─────────────────
veth-host                               veth-sandbox
10.200.0.1/24  ◄─────────────────────►  10.200.0.2/24
     │                                       │
     ▼                                       ▼
Proxy (10.200.0.1:3128)                Sandboxed process
     │                                  (can ONLY reach 10.200.0.1)
     ▼
Internet (via allow_hosts)
```

**Setup sequence:**

1. Create a new network namespace (`ip netns add sandbox-{id}`)
2. Create a veth pair connecting host and sandbox namespaces
3. Assign IPs: host side gets `10.200.0.1/24`, sandbox side gets `10.200.0.2/24`
4. Configure default route in sandbox to go via `10.200.0.1`
5. Proxy binds to `10.200.0.1:3128` instead of localhost
6. Child process enters the namespace via `setns()` before `exec`

The implementation lives in `crates/navigator-sandbox/src/sandbox/linux/netns.rs`.

**Requirements:**

- `CAP_SYS_ADMIN`: Required for creating namespaces and mount operations
- `CAP_NET_ADMIN`: Required for creating veth pairs and configuring interfaces
- `iproute2` package: Provides the `ip` command for namespace/interface setup

If namespace creation fails (e.g., missing capabilities), the sandbox logs a warning and continues
without network isolation. This allows development/testing without elevated privileges, though
production deployments should ensure capabilities are granted.

### Proxy Environment Variables

The sandbox exports proxy configuration to the child process:

- `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY`: Set to `http://10.200.0.1:3128` (with netns) or
  `http://127.0.0.1:3128` (without netns)

## Process Privileges

The sandbox supervisor can run as a more privileged user while the child process drops to a less
privileged account before `exec`. Configure this via `process.run_as_user` and
`process.run_as_group` in the policy. If unset, the child inherits the supervisor's user/group.

## Platform Extensibility

Platform-specific implementations are wired through `crates/navigator-sandbox/src/sandbox/mod.rs`.
Non-Linux platforms currently log a warning and skip enforcement, leaving room for a macOS backend
later without changing the public policy or CLI surface.
