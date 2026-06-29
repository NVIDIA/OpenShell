# Codebase grounding (supporting material for RFC 0012)

This file backs the claims [RFC 0012](./README.md) makes about the current
system, so a reviewer can verify them. It is supporting material, not part of the
normative RFC.

Verified against the RFC's parent commit `4ee27d99` (`origin/main` has since
advanced; these references are pinned to that parent). After #1650 the supervisor
split into `openshell-supervisor-network` (proxy, OPA, procfs identity) and
`openshell-supervisor-process` (spawn, SSH, netns creation, seccomp/Landlock).
References are line-pinned and will drift; the `rg` patterns let a reviewer
re-locate them.

| Claim | Reference |
|---|---|
| Agent container's seven capabilities | `crates/openshell-driver-kubernetes/src/driver.rs:1397` (base `SYS_ADMIN`/`NET_ADMIN`/`SYS_PTRACE`/`SYSLOG`), `:1403` (`SETUID`/`SETGID`/`DAC_READ_SEARCH` under userns) |
| Spec already separated from the netns handle | `crates/openshell-supervisor-process/src/process.rs:392`/`:406` (`ProcessHandle::spawn` takes `netns: Option<&NetworkNamespace>`) |
| Six `setns(CLONE_NEWNET)` call sites the contract's runtime interfaces replace (agent launch, SSH exec and forward, supervisor sessions); plus a `CLONE_NEWNS` at `:353` | `process.rs:549`, `ssh.rs:619`/`:1186`, `supervisor_session.rs:610`, `netns/mod.rs:226`/`:363` (`rg -n "CLONE_NEWNET" crates/openshell-supervisor-process`) |
| `nft`-absent fail-open (the invariant bug) | `crates/openshell-supervisor-process/src/netns/mod.rs:264`; logs and returns `Ok(())` at `:272`-`:277` |
| In-pod nftables ceiling is accept-by-default and rejects only TCP and UDP, so reading it back does not prove "only the proxy can egress" | `crates/openshell-supervisor-process/src/netns/nft_ruleset.rs:41` (`type filter hook output priority 0; policy accept`), `:43`-`:49` (proxy/loopback/established accept, then `reject` for IPv4 and IPv6 TCP and UDP only; other protocols and raw sockets pass once the host forwards the subnet). `rg -n "policy accept" crates/openshell-supervisor-process/src/netns` |
| Compute driver owns the execution domain (cgroup/resources, security context, device allocation set on the pod by the driver, not the supervisor) | `crates/openshell-driver-kubernetes/src/driver.rs` builds the pod/container spec; `rg -n "securityContext|resources|cdi\.k8s\.io|devices" crates/openshell-driver-kubernetes/src` |
| VM driver enables forwarding/MASQUERADE (host-forward assumption is load-bearing) | `crates/openshell-driver-vm/src/runtime.rs:417`/`:436` |
| No `StartSandbox` RPC (create and start fused; no driver start gate) | `proto/compute_driver.proto` has `CreateSandbox`/`StopSandbox`/`DeleteSandbox` only |
| Gateway already speaks exec/session/port-forward; no literal `Attach` | `proto/openshell.proto` (`ExecSandbox`, `ExecSandboxInteractive`, `CreateSshSession`, `ForwardTcp`) |
| Agent command via CLI/`SANDBOX_COMMAND`; no admission-bound spec field today; the `sleep infinity` placeholder resolves `sleep` from the agent image's own filesystem | `crates/openshell-sandbox/src/main.rs:331`; K8s driver sets `sleep infinity` at `driver.rs:1748` (`rg -n "sleep infinity" crates/openshell-driver-kubernetes/src`) |
| Init containers: `copy-self` (trusted, the OpenShell binary) and `workspace-init` (runs as root from the agent's own image, so its executables are image-provided); no native sidecars today | `driver.rs:182` (`WORKSPACE_INIT_CONTAINER_NAME`), `:880`, `:1072`; `rg -n "restart_policy|workspace-init" crates/openshell-driver-kubernetes/src` |
| Network policy is OPA per-CONNECT, not the boundary; identity via procfs | `crates/openshell-supervisor-network/src/opa.rs` (`NetworkInput`: `binary_path`/`binary_sha256`/`ancestors`/`cmdline_paths`), `procfs.rs`, glued in `proxy.rs:1432` |
| Static privilege ceiling on every spawned process; OPA never evaluates exec | `process.rs:400` (`drop_privileges`, seccomp/Landlock `enforce` from `SandboxPolicy`; SSH reaches the same `enter_netns_and_sandbox`) |
