---
name: sandbox-policy-opa-v1
overview: >
  Migrate sandbox network policy from a naive YAML hostname-allowlist to an
  embedded OPA (Rego) policy engine with process-identity binding via
  /proc, and SHA256 trust-on-first-use.
status: implemented
---

# OPA Sandbox Policy Engine — v1 Implementation Plan

## Threat Model

Agents running inside the sandbox can generate and execute arbitrary code
(Python scripts, curl, compiled binaries, etc.). This code must not be able to
reach network endpoints that are reserved for specific trusted binaries.

**Example:** Only `/usr/bin/node` should be able to reach
`api.anthropic.com:443`. A Python script written by an agent that attempts to
`curl api.anthropic.com` must be denied by the proxy even though the endpoint
is in the allowlist — because the calling binary is not `/usr/bin/node`.

~~**Note on interpreted apps:** Many tools are installed via package managers that
create shell-script wrappers. For example, the `claude` npm package installs a
shell script at `/usr/local/bin/claude` that `exec`s into `node`, so
`/proc/<pid>/exe` reports `/usr/bin/node` (the interpreter), not the wrapper.
Because the wrapper uses `exec`, the wrapper path disappears from the process
entirely — it is not in `/proc/<pid>/exe` or `/proc/<pid>/cmdline`. For
npm-style tools, policies should match the interpreter binary directly (e.g.
`/usr/bin/node`) rather than the wrapper path.~~

We now rely on installing Claude as a native binary, so the policy can directly allow connections from `/usr/local/bin/claude`.

**Layered defense model:**

- **Primary boundary:** Linux namespace isolation — only processes launched
  inside the sandbox can reach the proxy. The network namespace + veth pair
  ensures all traffic is funneled through the proxy; there is no direct
  internet access from within the sandbox.
- **Defense-in-depth:** Process identity binding via `/proc/<pid>/exe` — maps
  (binary, endpoint) pairs to named policies. The proxy resolves the calling
  binary and its ancestor chain for every CONNECT request.
- **Integrity:** SHA256 TOFU — on first use of a binary, the proxy computes
  its SHA256 hash and caches it as the "golden" hash for the lifetime of the
  sandbox. Any subsequent request from the same binary path must match the
  cached hash. A mismatch means the binary was replaced mid-sandbox and the
  request is denied. This is a trust-on-first-use model — the sandbox
  runtime is trusted at launch time, so binaries present at launch are assumed
  good.

## Current State

| Component | File | Behavior |
|-----------|------|----------|
| Policy loading | `crates/navigator-sandbox/src/policy.rs` | YAML deserialization via serde, or protobuf via gRPC |
| OPA engine | `crates/navigator-sandbox/src/opa.rs` | Embedded `regorus::Engine` with `Mutex` for thread safety |
| Process identity | `crates/navigator-sandbox/src/procfs.rs` | `/proc` reading: binary path (exe readlink, fail-closed), ancestor walk, TCP peer resolution. Also collects cmdline paths as a low-trust convenience signal. |
| Binary integrity | `crates/navigator-sandbox/src/identity.rs` | SHA256 TOFU cache with `Mutex<HashMap<PathBuf, String>>` |
| Proxy | `crates/navigator-sandbox/src/proxy.rs` | HTTP CONNECT proxy with OPA policy evaluation and legacy hostname allowlist fallback |
| Network isolation | `crates/navigator-sandbox/src/sandbox/linux/netns.rs` | Network namespace + veth pair forces all traffic through proxy |
| Syscall filtering | `crates/navigator-sandbox/src/sandbox/linux/seccomp.rs` | Blocks AF_INET/AF_INET6 direct socket creation in non-Allow mode |
| Orchestration | `crates/navigator-sandbox/src/lib.rs` | `run_sandbox()` → load policy → prepare fs → create netns → start proxy → spawn process |
| CLI | `crates/navigator-sandbox/src/main.rs` | `--policy <yaml>` or `--rego-policy` + `--rego-data` or `--sandbox-id` + `--navigator-endpoint` (gRPC) |
| Proto | `proto/sandbox.proto` | `SandboxPolicy`, `ProxyPolicy.allow_hosts` as repeated string |

## Architectural Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| OPA runtime | **Embedded via `regorus` crate** (`regorus = { version = "0.9", default-features = false, features = ["std", "arc", "glob"] }`). Thread safety: `Mutex<regorus::Engine>` because `eval` requires `&mut self`. | Pure-Rust OPA evaluator. No sidecar process, no latency penalty, no new failure domain. Self-contained proxy. |
| Process identity | **`/proc/<pid>/exe` readlink (fail-closed) + ancestor walk.** No fallback to `argv[0]` — if the exe symlink is unreadable the request is denied. Requires same-user or `CAP_SYS_PTRACE`. Cmdline paths are collected as a low-trust convenience signal (see Security Considerations). | Required by threat model — agent code must not reach binary-restricted endpoints. `argv[0]` is trivially spoofable and must never be used as a trusted identity source. |
| Parent-chain matching | **Implemented.** Ancestor walk via `/proc/<pid>/status` PPid chain with 64-depth safety limit. Stops at sandbox root PID or PID 1. | Enables policies like "allow Python subprocess spawned by glab to reach gitlab.com". |
| Cmdline path extraction | **Implemented.** Captures absolute paths from `/proc/<pid>/cmdline` for interpreter-based apps. The interpreter is the exe; the script path appears in cmdline. **Caveat:** cmdline is a convenience heuristic, not a security boundary — `argv` is writable by the owning process. Also, npm-style wrappers that `exec` into the interpreter may not leave the wrapper path in the final process's cmdline (e.g. `exec node cli.mjs` replaces the shell, so cmdline shows `node cli.mjs` not the wrapper path). For npm tools, prefer matching the interpreter binary directly (e.g. `/usr/bin/node`) or use glob patterns on module paths. | Covers shebang scripts and tools that pass script paths via argv. Not relied upon as a security boundary — namespace isolation is the primary control. |
| Glob patterns | **Implemented.** `glob.match(pattern, ["/"], path)` in Rego via regorus `glob` feature. `*` matches within a path segment, `**` across segments. `["/"]` delimiter prevents `*` from crossing `/` boundaries. | Enables policies like `"/usr/bin/*"` to match any binary in a directory without listing each one. |
| SHA256 enforcement | **Trust-on-first-use (TOFU)** | Policy lists binary paths only. Proxy hashes on first use, caches, enforces for sandbox lifetime. No build-pipeline coupling. |
| Policy loading | **`--rego-policy` + `--rego-data` CLI flags** | Explicit, no auto-detection. Falls back to `--policy` (YAML) when absent. |
| gRPC policy fetch | **Deferred, but API designed for it** | `OpaEngine::reload()` method ready for future hot-reload from navigator gateway. |

## Request Flow (TCP via Network Namespace + OPA)

```
1. Accept TCP connection from sandbox netns (via veth pair)
2. Resolve peer PID: /proc/<sandbox_pid>/net/tcp → socket inode → FD scan → PID
3. Binary identity: /proc/<pid>/exe → binary path (fail-closed, no argv[0] fallback)
4. Ancestor walk: PPid chain → ancestor binary paths (up to 64 levels, stop at sandbox root)
5. Cmdline paths: /proc/<pid>/cmdline + ancestor cmdlines → absolute paths (excl. exe paths)
6. SHA256 TOFU: verify_or_cache(binary) + verify_or_cache(each ancestor)
7. Build OPA input: {exec: {path, ancestors, cmdline_paths}, network: {host, port}}
8. regorus eval → allow_network, deny_reason, matched_network_policy
9. Log: binary, pid, ancestors, cmdline, action, engine, policy, reason
```

## Implementation

### Dependencies

In `crates/navigator-sandbox/Cargo.toml`:

```toml
# OPA policy evaluation (no default features — full-opa pulls in opa-runtime which requires git in build)
regorus = { version = "0.9", default-features = false, features = ["std", "arc", "glob"] }
```

Existing deps already provide: `sha2` (0.10), `hex` (0.4), `tokio` (workspace),
`nix` (workspace).

### Module: `crates/navigator-sandbox/src/opa.rs`

Wraps `regorus::Engine` for OPA policy evaluation. Thread-safe via
`Mutex<regorus::Engine>` because `eval` requires `&mut self`.

```rust
pub struct OpaEngine {
    engine: Mutex<regorus::Engine>,
}

impl OpaEngine {
    /// Load policy and data from `.rego` file paths.
    pub fn from_files(policy_path: &Path, data_path: &Path) -> Result<Self>;

    /// Load policy and data from strings (for future gRPC bundles).
    pub fn from_strings(policy: &str, data: &str) -> Result<Self>;

    /// Evaluate a network access request.
    /// Returns PolicyDecision { allowed, reason, matched_policy }.
    pub fn evaluate_network(&self, input: &NetworkInput) -> Result<PolicyDecision>;

    /// Reload policy and data from strings (for future gRPC hot-reload).
    /// Replaces the entire engine atomically.
    pub fn reload(&self, policy: &str, data: &str) -> Result<()>;

    /// Query static policy data (filesystem, landlock, process config).
    /// Used at startup to extract sandbox setup configuration from Rego data.
    pub fn query_sandbox_config(&self) -> Result<SandboxConfig>;
}

pub struct NetworkInput {
    pub host: String,
    pub port: u16,
    pub binary_path: PathBuf,
    pub binary_sha256: String,
    /// Ancestor binary paths from process tree walk (parent, grandparent, ...).
    pub ancestors: Vec<PathBuf>,
    /// Absolute paths extracted from /proc/<pid>/cmdline of the socket-owning
    /// process and its ancestors.
    pub cmdline_paths: Vec<PathBuf>,
}

pub struct PolicyDecision {
    pub allowed: bool,
    pub reason: String,
    pub matched_policy: Option<String>,
}

pub struct SandboxConfig {
    pub filesystem: FilesystemPolicy,
    pub landlock: LandlockPolicy,
    pub process: ProcessPolicy,
}
```

**OPA input JSON shape:**

```json
{
  "exec": {
    "path": "/usr/bin/node",
    "ancestors": ["/usr/bin/bash"],
    "cmdline_paths": ["/home/sandbox/.npm/lib/node_modules/claude/cli.mjs"]
  },
  "network": {
    "host": "api.anthropic.com",
    "port": 443
  }
}
```

Note: `cmdline_paths` captures absolute paths from `/proc/<pid>/cmdline` argv
entries. This is a low-trust convenience signal — see Security Considerations.
For npm tools where the wrapper uses `exec`, the wrapper path (e.g.
`/usr/local/bin/claude`) will not appear here; only paths visible in the final
process's argv are captured.

### Module: `crates/navigator-sandbox/src/procfs.rs`

Linux-only `/proc` reading for process identity. Functions gated with
`#[cfg(target_os = "linux")]` except `file_sha256` which is cross-platform.

**Fail-closed identity resolution:** `binary_path()` uses only
`/proc/<pid>/exe` readlink. It never falls back to `/proc/<pid>/cmdline`
(`argv[0]`) because argv is trivially spoofable by any process. If the exe
symlink is unreadable (e.g. different user without `CAP_SYS_PTRACE`), the
function returns an error and the proxy denies the request.

```rust
/// Read binary path via /proc/<pid>/exe readlink. Fails hard (no argv[0] fallback)
/// if the exe symlink is unreadable — request will be denied.
pub fn binary_path(pid: i32) -> Result<PathBuf>;

/// Resolve TCP peer binary path and PID via /proc/<sandbox_pid>/net/tcp → socket
/// inode → FD scan → PID → /proc/<pid>/exe.
pub fn resolve_tcp_peer_identity(sandbox_pid: u32, peer_port: u16) -> Result<(PathBuf, u32)>;

/// Read the PPid (parent PID) from /proc/<pid>/status.
pub fn read_ppid(pid: u32) -> Option<u32>;

/// Walk the process tree upward from pid, collecting ancestor binary paths.
/// Stops at PID 1, stop_pid (sandbox root), or after 64 ancestors.
pub fn collect_ancestor_binaries(pid: u32, stop_pid: u32) -> Vec<PathBuf>;

/// Extract absolute paths from /proc/<pid>/cmdline (argv entries starting with /).
/// Note: cmdline is a convenience heuristic, not a security boundary.
pub fn cmdline_absolute_paths(pid: u32) -> Vec<PathBuf>;

/// Collect deduplicated cmdline paths for PID + ancestors, excluding paths
/// already captured via exe (to avoid duplicates with binary/ancestor lists).
pub fn collect_cmdline_paths(pid: u32, stop_pid: u32, exclude: &[PathBuf]) -> Vec<PathBuf>;

/// Compute SHA256 hash of a file, hex-encoded (cross-platform).
pub fn file_sha256(path: &Path) -> Result<String>;
```

### Module: `crates/navigator-sandbox/src/identity.rs`

SHA256 trust-on-first-use cache. Thread-safe for concurrent proxy connections.

```rust
pub struct BinaryIdentityCache {
    hashes: Mutex<HashMap<PathBuf, String>>,
}

impl BinaryIdentityCache {
    pub fn new() -> Self;

    /// On first call for a path: compute SHA256, cache, return hash.
    /// On subsequent calls: compute SHA256, compare with cached value.
    /// Returns Ok(hash) if valid, Err if hash mismatch (binary tampered).
    pub fn verify_or_cache(&self, path: &Path) -> Result<String>;
}
```

### Modified: `crates/navigator-sandbox/src/proxy.rs`

The proxy evaluates policy via `ConnectDecision` with full identity context:

```rust
struct ConnectDecision {
    allowed: bool,
    /// "opa" or "legacy"
    engine: &'static str,
    /// Resolved binary path (OPA only).
    binary: Option<PathBuf>,
    /// PID owning the socket (OPA only).
    binary_pid: Option<u32>,
    /// Ancestor binary paths from process tree walk (OPA only).
    ancestors: Vec<PathBuf>,
    /// Cmdline-derived absolute paths (OPA only).
    cmdline_paths: Vec<PathBuf>,
    /// Name of the matched policy rule (OPA allow only).
    matched_policy: Option<String>,
    /// Deny reason or error context.
    reason: String,
}
```

**Key functions:**

- `evaluate_opa_tcp` (Linux): full flow — resolve peer identity via
  `/proc/net/tcp` → ancestor walk → cmdline paths → TOFU verify all binaries →
  OPA eval. Uses the sandbox PID stored in `AtomicU32` to scope the
  `/proc/net/tcp` lookup and ancestor walk stop condition.
- `evaluate_opa_tcp` (non-Linux): stub returning deny with
  "identity binding unavailable on this platform".
- `evaluate_legacy`: hostname allowlist via `is_allowed()` (unchanged).

**Unified log line:** Every CONNECT request produces a single `info!` log with:
`src_addr`, `src_port`, `proxy_addr`, `dst_host`, `dst_port`, `binary`,
`binary_pid`, `ancestors`, `cmdline`, `action`, `engine`, `policy`, `reason`.

### Modified: `crates/navigator-sandbox/src/lib.rs`

`run_sandbox()` accepts `rego_policy` and `rego_data` parameters. When provided,
`load_policy()` initializes the OPA engine and identity cache:

```rust
pub async fn run_sandbox(
    // ... existing params ...
    rego_policy: Option<String>,
    rego_data: Option<String>,
    // ... rest ...
) -> Result<i32> {
    let (policy, opa_engine) = load_policy(
        policy_path, sandbox_id, navigator_endpoint,
        rego_policy, rego_data,
    ).await?;

    let identity_cache = opa_engine.as_ref().map(|_| {
        Arc::new(BinaryIdentityCache::new())
    });

    // Shared PID: set after process spawn so the proxy can look up
    // the sandbox process's /proc/net/tcp for identity binding.
    let sandbox_pid = Arc::new(AtomicU32::new(0));

    // ... proxy and process startup ...
    // sandbox_pid.store(handle.pid(), Ordering::Release);
}
```

`load_policy()` priority: Rego files → gRPC → YAML → error.

### Modified: `crates/navigator-sandbox/src/main.rs`

CLI flags:

```rust
/// Path to Rego policy file for OPA-based network access control.
/// Requires --rego-data to also be set.
#[arg(long, env = "NAVIGATOR_REGO_POLICY")]
rego_policy: Option<String>,

/// Path to Rego data file containing network policies and sandbox config.
/// Requires --rego-policy to also be set.
#[arg(long, env = "NAVIGATOR_REGO_DATA")]
rego_data: Option<String>,
```

## Rego Policy

The Rego policy (`sandbox-policy.rego`) implements four `binary_allowed` clauses:

1. **Exact path match** (high trust) — guarded by `not contains(b.path, "*")`,
   matches `b.path == exec.path`. Source: `/proc/<pid>/exe` readlink.
2. **Ancestor exact path match** (high trust) — matches any
   `exec.ancestors[_]` against `b.path` (e.g., Python subprocess spawned by
   glab can reach gitlab.com). Source: `/proc/<pid>/exe` readlink per ancestor.
3. **Cmdline exact path match** (low trust) — matches any
   `exec.cmdline_paths[_]` against `b.path`. Source: `/proc/<pid>/cmdline`
   which is spoofable. Useful as a convenience heuristic for shebang scripts
   but should not be relied upon as a security boundary.
4. **Glob pattern match** (trust depends on source) — when `b.path` contains
   `*`, matches against all paths (binary + ancestors + cmdline) via
   `glob.match(b.path, ["/"], p)`.

Endpoint matching is host (case-insensitive via `lower()` on both sides) + port.

## Migration Strategy

| Path | Policy source | Identity binding | OPA evaluation |
|------|--------------|------------------|----------------|
| `--policy <file.yaml>` | YAML file | No | No (legacy `is_allowed`) |
| `--sandbox-id` + `--navigator-endpoint` | gRPC protobuf | No | No (legacy) |
| `--rego-policy` + `--rego-data` | Rego files | Yes | Yes |

- YAML and gRPC paths continue to work unchanged — no breaking changes.
- Rego path is new and opt-in.
- YAML does not gain identity binding (intentional — migrate to Rego for that).

## Testing

### Test counts by module

| Module | Tests | Notes |
|--------|-------|-------|
| `opa.rs` | 21 | Policy evaluation, ancestors, cmdline, glob, reload, sandbox config |
| `procfs.rs` | 11 | SHA256 hashing (cross-platform), Linux-only `/proc` reading |
| `identity.rs` | 3 | TOFU cache, hash mismatch detection |
| `proxy.rs` | 3 | Allowlist matching, proxy allow/deny (Linux-only) |

### OPA tests added for v1 features

| Test | What it verifies |
|------|-----------------|
| `ancestor_binary_allowed` | Ancestor match allows access (glab → python subprocess) |
| `no_ancestor_match_denied` | Non-matching ancestor is denied |
| `deep_ancestor_chain_matches` | Match works at depth > 1 in ancestor chain |
| `empty_ancestors_falls_back_to_direct` | Direct path match still works with empty ancestors |
| `glob_pattern_matches_binary` | `"/usr/bin/*"` matches `/usr/bin/node` |
| `glob_pattern_matches_ancestor` | `"/usr/local/bin/*"` matches ancestor `/usr/local/bin/claude` |
| `glob_pattern_no_cross_segment` | `"/usr/bin/*"` does NOT match `/usr/bin/subdir/node` |
| `cmdline_path_matches_script_binary` | Cmdline path `/usr/local/bin/my-tool` matches policy binary |
| `cmdline_path_no_match_denied` | Non-matching cmdline path is denied |
| `cmdline_glob_pattern_matches` | Glob pattern matches via cmdline path |

## Security Considerations

**Trust boundaries and what each layer guarantees:**

| Layer | Source | Trust level | Notes |
|-------|--------|-------------|-------|
| Binary path | `/proc/<pid>/exe` readlink | **High** — kernel-maintained, not spoofable by the process | Primary identity signal. Fails closed if unreadable. |
| Ancestor chain | `/proc/<pid>/status` PPid walk + exe readlink | **High** — same kernel-maintained source per ancestor | Enables subprocess delegation (e.g. glab spawns python). |
| SHA256 TOFU | Hash of file at exe path | **High** — detects binary replacement mid-sandbox | Does not protect against pre-existing malicious binaries at sandbox launch. |
| Cmdline paths | `/proc/<pid>/cmdline` | **Low** — `argv` is writable by the owning process | Convenience heuristic for script detection. Not a security boundary. |
| Namespace isolation | Linux netns + veth | **High** — kernel-enforced, only sandbox traffic reaches proxy | Primary security boundary. Identity binding is defense-in-depth. |

**Known limitations:**

- **Cmdline spoofability:** A malicious process can set `argv[0]` to any value.
  Cmdline matching is a convenience for identifying interpreter-based tools, not
  a security control. The namespace boundary is the primary defense.
- **npm wrapper cmdline:** npm-style wrappers that use `exec node cli.mjs`
  replace the shell process, so the wrapper path (e.g. `/usr/local/bin/claude`)
  does not appear in node's final cmdline. For npm tools, match the interpreter
  binary directly (`/usr/bin/node`) or use glob patterns on module paths.
- **TOFU scope:** Only exe binaries (from `/proc/<pid>/exe`) and their ancestors
  are SHA256-hashed. Script files referenced via cmdline are path-matched but
  not integrity-checked. See v2 roadmap for cmdline script TOFU.

## v2 Roadmap (Out of Scope)

These items are explicitly deferred:

- **Cmdline script TOFU** — SHA256 hash script files (e.g. `cli.mjs`) not just
  interpreter binaries. Currently only exe binaries are hashed; scripts
  referenced via cmdline are matched by path but not integrity-checked.
- **Namespace inode assertion** — verify `/proc/<pid>/ns/net` matches sandbox
  netns inode for defense against PID reuse races.
- **gRPC policy bundles** — serving Rego from navigator gateway.
- **Policy hot-reload** — `OpaEngine::reload()` exists but not wired to gRPC.
- **Multi-tenant policy** — per-tenant policy namespacing in OPA data.
- **OPA sidecar mode** — external OPA server for centralized decision logging.

## References

- Dev policy: [`dev-sandbox-policy.rego`](/dev-sandbox-policy.rego), [`dev-sandbox-policy-data.rego`](/dev-sandbox-policy-data.rego)
- OPA engine: [`crates/navigator-sandbox/src/opa.rs`](/crates/navigator-sandbox/src/opa.rs)
- Process identity: [`crates/navigator-sandbox/src/procfs.rs`](/crates/navigator-sandbox/src/procfs.rs)
- Binary integrity: [`crates/navigator-sandbox/src/identity.rs`](/crates/navigator-sandbox/src/identity.rs)
- Proxy implementation: [`crates/navigator-sandbox/src/proxy.rs`](/crates/navigator-sandbox/src/proxy.rs)
- Sandbox orchestration: [`crates/navigator-sandbox/src/lib.rs`](/crates/navigator-sandbox/src/lib.rs)
- Policy loading: [`crates/navigator-sandbox/src/policy.rs`](/crates/navigator-sandbox/src/policy.rs)
- Network namespace: [`crates/navigator-sandbox/src/sandbox/linux/netns.rs`](/crates/navigator-sandbox/src/sandbox/linux/netns.rs)
- Seccomp rules: [`crates/navigator-sandbox/src/sandbox/linux/seccomp.rs`](/crates/navigator-sandbox/src/sandbox/linux/seccomp.rs)
- Regorus crate: [github.com/microsoft/regorus](https://github.com/microsoft/regorus)
