# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

@AGENTS.md

## Commands

### Build and check

```bash
cargo build --workspace           # Build all Rust crates
cargo check --workspace           # Fast compile check (no output)
cargo clippy --workspace --all-targets  # Lint
cargo fmt --all                   # Format Rust code
```

### Run a single Rust test

```bash
cargo test -p <crate-name> <test_name>
# Example:
cargo test -p openshell-sandbox policy
```

### Python

```bash
uv run pytest python/             # Unit tests
uv run ruff check python/         # Lint
uv run ruff format python/        # Format
uv run ty check python/           # Type check
mise run python:proto             # Regenerate gRPC stubs from proto/ into python/openshell/_proto/
```

### Cluster and sandbox

```bash
mise run cluster   # Bootstrap or incremental deploy to local K3s
mise run sandbox   # Create/reconnect dev sandbox (deploys cluster first if needed)
```

## Architecture

OpenShell runs AI agents inside sandboxed Kubernetes pods on a single-node K3s cluster (itself a Docker container). The key insight is that **all agent egress traffic is forced through an in-process HTTP CONNECT proxy** — there is no iptables magic; it uses a Linux network namespace veth pair (10.200.0.1 ↔ 10.200.0.2).

### Crate dependencies (simplified)

```
openshell-cli  ──────────────────────────────> openshell-core
openshell-server ──> openshell-policy, openshell-router, openshell-core
openshell-sandbox ──> openshell-policy, openshell-router, openshell-core
openshell-bootstrap ──> openshell-core
openshell-tui ──> openshell-core
```

`openshell-policy` and `openshell-router` are shared libraries used by both `openshell-server` (gateway) and `openshell-sandbox` (in-pod supervisor).

### Control plane vs. data plane split

- **Gateway** (`openshell-server`): Manages sandbox lifecycle via Kubernetes CRDs, stores state in SQLite, exposes gRPC+HTTP on a single mTLS-multiplexed port (8080 internal / 30051 NodePort). Handles CLI auth, SSH bridging, and config/policy distribution.
- **Sandbox supervisor** (`openshell-sandbox`): Runs privileged inside each sandbox pod. Polls the gateway over gRPC (mTLS) for policy updates and provider credentials (`GetSandboxSettings`, `GetProviderEnvironment`, `GetInferenceBundle`). Hosts the embedded SSH server (russh :2222), HTTP CONNECT proxy (:3128), and OPA engine (regorus, in-process — no OPA daemon).
- **Agent process**: Runs unprivileged inside the same pod with Landlock filesystem isolation + seccomp BPF. Sees only the proxied network.

### Policy evaluation

Policies are Rego documents evaluated by `regorus` (a pure-Rust OPA engine). Every outbound connection attempt from the agent is evaluated synchronously in the proxy before the TCP connection is allowed. L7 inspection uses TLS MITM via an in-process cert cache.

### Inference routing

`openshell-router` runs **inside the sandbox**, not in the gateway. The gateway pushes route configuration and credentials via `GetInferenceBundle`; the sandbox executes HTTP requests directly to inference backends (vLLM, LM Studio, NVIDIA NIM, etc.). Inference routing is distinct from general egress policy.

### Python SDK

The Python package is a [maturin](https://www.maturin.rs/) wheel (PyO3 + Rust). The CLI binary is embedded in the wheel. Proto stubs in `python/openshell/_proto/` are generated from `proto/` by `mise run python:proto` and committed — regenerate them whenever `.proto` files change.

### SSH tunnel

CLI connects to sandbox via HTTP CONNECT upgrade at `/connect/ssh` on the gateway. The gateway authenticates with a session token and bridges to the sandbox SSH server using the NSSH1 HMAC-SHA256 handshake protocol. File sync uses tar-over-SSH (no rsync dependency).

### DCO

All commits require a `Signed-off-by` line: `git commit -s`.
