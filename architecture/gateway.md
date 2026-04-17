# Gateway Architecture

## Overview

`openshell-server` is the gateway -- the central control plane for a cluster. It exposes two gRPC services (OpenShell and Inference) and HTTP endpoints on a single multiplexed port, manages sandbox lifecycle through Kubernetes CRDs, persists state in SQLite or Postgres, and provides SSH tunneling into sandbox pods. The gateway coordinates all interactions between clients, the Kubernetes cluster, and the persistence layer.

## Architecture Diagram

The following diagram shows the major components inside the gateway process and their relationships.

```mermaid
graph TD
    Client["gRPC / HTTP Client"]
    TCP["TCP Listener"]
    TLS["TLS Acceptor<br/>(optional)"]
    MUX["MultiplexedService"]
    GRPC_ROUTER["GrpcRouter"]
    NAV["OpenShellServer<br/>(OpenShell service)"]
    INF["InferenceServer<br/>(Inference service)"]
    HTTP["HTTP Router<br/>(Axum)"]
    HEALTH["Health Endpoints"]
    SSH_TUNNEL["SSH Tunnel<br/>(/connect/ssh)"]
    STORE["Store<br/>(SQLite / Postgres)"]
    K8S["Kubernetes API"]
    WATCHER["Sandbox Watcher"]
    EVENT_TAILER["Kube Event Tailer"]
    WATCH_BUS["SandboxWatchBus"]
    LOG_BUS["TracingLogBus"]
    PLAT_BUS["PlatformEventBus"]
    INDEX["SandboxIndex"]

    Client --> TCP
    TCP --> TLS
    TLS --> MUX
    MUX -->|"content-type: application/grpc"| GRPC_ROUTER
    MUX -->|"other"| HTTP
    GRPC_ROUTER -->|"/openshell.inference.v1.Inference/*"| INF
    GRPC_ROUTER -->|"all other paths"| NAV
    HTTP --> HEALTH
    HTTP --> SSH_TUNNEL
    NAV --> STORE
    NAV --> K8S
    INF --> STORE
    SSH_TUNNEL --> STORE
    SSH_TUNNEL --> K8S
    WATCHER --> K8S
    WATCHER --> STORE
    WATCHER --> WATCH_BUS
    WATCHER --> INDEX
    EVENT_TAILER --> K8S
    EVENT_TAILER --> PLAT_BUS
    EVENT_TAILER --> INDEX
    LOG_BUS --> PLAT_BUS
```

## Source Layout

| Module | File | Purpose |
|--------|------|---------|
| Entry point | `crates/openshell-server/src/main.rs` | CLI argument parsing, config assembly, tracing setup, calls `run_server` |
| Gateway runtime | `crates/openshell-server/src/lib.rs` | `ServerState` struct, `run_server()` accept loop |
| Protocol mux | `crates/openshell-server/src/multiplex.rs` | `MultiplexService`, `MultiplexedService`, `GrpcRouter`, `BoxBody` |
| gRPC: OpenShell | `crates/openshell-server/src/grpc.rs` | `OpenShellService` -- sandbox CRUD, provider CRUD, watch, exec, SSH sessions, policy delivery |
| gRPC: Inference | `crates/openshell-server/src/inference.rs` | `InferenceService` -- cluster inference config (set/get) and sandbox inference bundle delivery |
| HTTP | `crates/openshell-server/src/http.rs` | Health endpoints, merged with SSH tunnel router |
| Browser auth | `crates/openshell-server/src/auth.rs` | Cloudflare browser login relay at `/auth/connect` |
| SSH tunnel | `crates/openshell-server/src/ssh_tunnel.rs` | HTTP CONNECT handler at `/connect/ssh` |
| WS tunnel | `crates/openshell-server/src/ws_tunnel.rs` | WebSocket tunnel handler at `/_ws_tunnel` for Cloudflare-fronted clients |
| TLS | `crates/openshell-server/src/tls.rs` | `TlsAcceptor` wrapping rustls with ALPN |
| Persistence | `crates/openshell-server/src/persistence/mod.rs` | `Store` enum (SQLite/Postgres), generic object CRUD, protobuf codec |
| Persistence: SQLite | `crates/openshell-server/src/persistence/sqlite.rs` | `SqliteStore` with sqlx |
| Persistence: Postgres | `crates/openshell-server/src/persistence/postgres.rs` | `PostgresStore` with sqlx |
| Compute runtime | `crates/openshell-server/src/compute/mod.rs` | `ComputeRuntime`, gateway-owned sandbox lifecycle orchestration over a compute backend |
| Compute driver: Kubernetes | `crates/openshell-driver-kubernetes/src/driver.rs` | Kubernetes CRD create/delete, endpoint resolution, watch stream, pod template translation |
| Compute driver: VM | `crates/openshell-driver-vm/src/driver.rs` | Per-sandbox microVM create/delete, localhost endpoint resolution, watch stream, supervisor-only guest boot |
| Sandbox index | `crates/openshell-server/src/sandbox_index.rs` | `SandboxIndex` -- in-memory name/pod-to-id correlation |
| Watch bus | `crates/openshell-server/src/sandbox_watch.rs` | `SandboxWatchBus` -- in-memory broadcast for persisted sandbox updates |
| Tracing bus | `crates/openshell-server/src/tracing_bus.rs` | `TracingLogBus` -- captures tracing events keyed by `sandbox_id` |

Proto definitions consumed by the gateway:

| Proto file | Package | Defines |
|------------|---------|---------|
| `proto/openshell.proto` | `openshell.v1` | `OpenShell` service, public sandbox resource model, provider/SSH/watch messages |
| `proto/compute_driver.proto` | `openshell.compute.v1` | Internal `ComputeDriver` service, driver-native sandbox observations, endpoint resolution, compute watch stream envelopes |
| `proto/inference.proto` | `openshell.inference.v1` | `Inference` service: `SetClusterInference`, `GetClusterInference`, `GetInferenceBundle` |
| `proto/datamodel.proto` | `openshell.datamodel.v1` | `Provider` |
| `proto/sandbox.proto` | `openshell.sandbox.v1` | Sandbox supervisor policy, settings, and config messages |

## Startup Sequence

The gateway boots in `main()` (`crates/openshell-server/src/main.rs`) and proceeds through these steps:

1. **Install rustls crypto provider** -- `aws_lc_rs::default_provider().install_default()`.
2. **Parse CLI arguments** -- `Args::parse()` via `clap`. Every flag has a corresponding environment variable (see [Configuration](#configuration)).
3. **Initialize tracing** -- Creates a `TracingLogBus` and installs a tracing subscriber that writes to stdout and publishes log events keyed by `sandbox_id` into the bus.
4. **Build `Config`** -- Assembles a `openshell_core::Config` from the parsed arguments.
5. **Call `run_server()`** (`crates/openshell-server/src/lib.rs`):
   1. Connect to the persistence store (`Store::connect`), which auto-detects SQLite vs Postgres from the URL prefix and runs migrations.
   2. Create `ComputeRuntime` with a `ComputeDriver` implementation selected by `OPENSHELL_DRIVERS`:
      - `kubernetes` wraps `KubernetesComputeDriver` in `ComputeDriverService`, so the gateway uses the `openshell.compute.v1.ComputeDriver` RPC surface even without transport.
      - `vm` spawns the sibling `openshell-driver-vm` binary as a local compute-driver process, connects to it over a Unix domain socket, and keeps the libkrun/rootfs runtime out of the gateway binary.
   3. Build `ServerState` (shared via `Arc<ServerState>` across all handlers).
   4. **Spawn background tasks**:
      - `ComputeRuntime::spawn_watchers` -- consumes the compute-driver watch stream, republishes platform events, and runs a periodic `ListSandboxes` snapshot reconcile so the store-backed public sandbox reads stay aligned with the compute driver.
   5. Create `MultiplexService`.
   6. Bind `TcpListener` on `config.bind_address`.
   7. Optionally create `TlsAcceptor` from cert/key files.
   8. Enter the accept loop: for each connection, spawn a tokio task that optionally performs a TLS handshake, then calls `MultiplexService::serve()`.

## Configuration

All configuration is via CLI flags with environment variable fallbacks. The `--db-url` flag is the only required argument.

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--port` | `OPENSHELL_SERVER_PORT` | `8080` | TCP listen port (binds `0.0.0.0`) |
| `--log-level` | `OPENSHELL_LOG_LEVEL` | `info` | Tracing log level filter |
| `--tls-cert` | `OPENSHELL_TLS_CERT` | None | Path to PEM certificate file |
| `--tls-key` | `OPENSHELL_TLS_KEY` | None | Path to PEM private key file |
| `--tls-client-ca` | `OPENSHELL_TLS_CLIENT_CA` | None | Path to PEM CA cert for mTLS client verification |
| `--disable-tls` | `OPENSHELL_DISABLE_TLS` | `false` | Listen on plaintext HTTP behind a trusted reverse proxy or tunnel |
| `--disable-gateway-auth` | `OPENSHELL_DISABLE_GATEWAY_AUTH` | `false` | Keep TLS enabled but allow no-certificate clients and rely on application-layer auth |
| `--client-tls-secret-name` | `OPENSHELL_CLIENT_TLS_SECRET_NAME` | None | K8s secret name to mount into sandbox pods for mTLS |
| `--db-url` | `OPENSHELL_DB_URL` | *required* | Database URL (`sqlite:...` or `postgres://...`). The Helm chart defaults to `sqlite:/var/openshell/openshell.db` (persistent volume). In-memory SQLite (`sqlite::memory:?cache=shared`) works for ephemeral/test environments but data is lost on restart. |
| `--sandbox-namespace` | `OPENSHELL_SANDBOX_NAMESPACE` | `default` | Kubernetes namespace for sandbox CRDs |
| `--sandbox-image` | `OPENSHELL_SANDBOX_IMAGE` | None | Default container image for sandbox pods |
| `--grpc-endpoint` | `OPENSHELL_GRPC_ENDPOINT` | None | gRPC endpoint reachable from within the cluster (for sandbox callbacks) |
| `--drivers` | `OPENSHELL_DRIVERS` | `kubernetes` | Compute backend to use. Current options are `kubernetes` and `vm`. |
| `--vm-driver-state-dir` | `OPENSHELL_VM_DRIVER_STATE_DIR` | `target/openshell-vm-driver` | Host directory for VM sandbox rootfs, console logs, and runtime state |
| `--vm-compute-driver-bin` | `OPENSHELL_VM_COMPUTE_DRIVER_BIN` | sibling `openshell-driver-vm` binary | Local VM compute-driver process spawned by the gateway |
| `--vm-krun-log-level` | `OPENSHELL_VM_KRUN_LOG_LEVEL` | `1` | libkrun log level for VM helper processes |
| `--vm-driver-vcpus` | `OPENSHELL_VM_DRIVER_VCPUS` | `2` | Default vCPU count for VM sandboxes |
| `--vm-driver-mem-mib` | `OPENSHELL_VM_DRIVER_MEM_MIB` | `2048` | Default memory allocation for VM sandboxes in MiB |
| `--vm-tls-ca` | `OPENSHELL_VM_TLS_CA` | None | CA cert copied into VM guests for gateway mTLS |
| `--vm-tls-cert` | `OPENSHELL_VM_TLS_CERT` | None | Client cert copied into VM guests for gateway mTLS |
| `--vm-tls-key` | `OPENSHELL_VM_TLS_KEY` | None | Client private key copied into VM guests for gateway mTLS |
| `--ssh-gateway-host` | `OPENSHELL_SSH_GATEWAY_HOST` | `127.0.0.1` | Public hostname returned in SSH session responses |
| `--ssh-gateway-port` | `OPENSHELL_SSH_GATEWAY_PORT` | `8080` | Public port returned in SSH session responses |
| `--ssh-connect-path` | `OPENSHELL_SSH_CONNECT_PATH` | `/connect/ssh` | HTTP path for SSH CONNECT/upgrade |
| `--sandbox-ssh-port` | `OPENSHELL_SANDBOX_SSH_PORT` | `2222` | SSH listen port inside sandbox pods |
| `--ssh-handshake-secret` | `OPENSHELL_SSH_HANDSHAKE_SECRET` | None | Shared HMAC-SHA256 secret for gateway-to-sandbox handshake |
| `--ssh-handshake-skew-secs` | `OPENSHELL_SSH_HANDSHAKE_SKEW_SECS` | `300` | Allowed clock skew (seconds) for SSH handshake timestamps |

## Shared State

All handlers share an `Arc<ServerState>` (`crates/openshell-server/src/lib.rs`):

```rust
pub struct ServerState {
    pub config: Config,
    pub store: Arc<Store>,
    pub compute: ComputeRuntime,
    pub sandbox_index: SandboxIndex,
    pub sandbox_watch_bus: SandboxWatchBus,
    pub tracing_log_bus: TracingLogBus,
    pub ssh_connections_by_token: Mutex<HashMap<String, u32>>,
    pub ssh_connections_by_sandbox: Mutex<HashMap<String, u32>>,
    pub settings_mutex: tokio::sync::Mutex<()>,
}
```

- **`store`** -- persistence backend (SQLite or Postgres) for all object types.
- **`compute`** -- gateway-owned compute orchestration. Persists sandbox lifecycle transitions, validates create requests through the compute backend, resolves exec/SSH endpoints, consumes the backend watch stream, and periodically reconciles the store against `ComputeDriver/ListSandboxes` snapshots.
- **`sandbox_index`** -- in-memory bidirectional index mapping sandbox names and agent pod names to sandbox IDs. Updated from compute-driver sandbox snapshots.
- **`sandbox_watch_bus`** -- `broadcast`-based notification bus keyed by sandbox ID. Producers call `notify(&id)` when the persisted sandbox record changes; consumers in `WatchSandbox` streams receive `()` signals and re-read the record.
- **`tracing_log_bus`** -- captures `tracing` events that include a `sandbox_id` field and republishes them as `SandboxLogLine` messages. Maintains a per-sandbox tail buffer (default 200 entries). Also contains a nested `PlatformEventBus` for compute-driver platform events.
- **`settings_mutex`** -- serializes settings mutations (global and sandbox) to prevent read-modify-write races. Held for the duration of any setting set/delete or global policy set/delete operation. See [Gateway Settings Channel](gateway-settings.md#global-policy-lifecycle).

## Protocol Multiplexing

All traffic (gRPC and HTTP) shares a single TCP port. Multiplexing happens at the request level, not the connection level.

### Connection Handling

`MultiplexService::serve()` (`crates/openshell-server/src/multiplex.rs`) creates per-connection service instances:

1. Each accepted TCP stream (optionally TLS-wrapped) is passed to `hyper_util::server::conn::auto::Builder`, which auto-negotiates HTTP/1.1 or HTTP/2.
2. The builder calls `serve_connection_with_upgrades()`, which supports HTTP upgrades (needed for the SSH tunnel's CONNECT method).
3. For each request, `MultiplexedService` inspects the `content-type` header:
   - **Starts with `application/grpc`** -- routes to `GrpcRouter`.
   - **Anything else** -- routes to the Axum HTTP router.

### gRPC Sub-Routing

`GrpcRouter` (`crates/openshell-server/src/multiplex.rs`) further routes gRPC requests by URI path prefix:

- Paths starting with `/openshell.inference.v1.Inference/` go to `InferenceServer`.
- All other gRPC paths go to `OpenShellServer`.

### Body Type Normalization

Both gRPC and HTTP handlers produce different response body types. `MultiplexedService` normalizes them through a custom `BoxBody` wrapper (an `UnsyncBoxBody<Bytes, Box<dyn Error>>`) so that Hyper receives a uniform response type.

### TLS + mTLS

When TLS is enabled (`crates/openshell-server/src/tls.rs`):

- `TlsAcceptor::from_files()` loads PEM certificates and keys via `rustls_pemfile`, builds a `rustls::ServerConfig`, and configures ALPN to advertise `h2` and `http/1.1`.
- When a client CA path is provided (`--tls-client-ca`), the server enforces mutual TLS using `WebPkiClientVerifier` by default. In Cloudflare-fronted deployments, `--disable-gateway-auth` keeps TLS enabled but allows no-certificate clients so the edge can forward a JWT instead.
- `--disable-tls` removes gateway-side TLS entirely and serves plaintext HTTP behind a trusted reverse proxy or tunnel.
- Supports PKCS#1, PKCS#8, and SEC1 private key formats.
- The TLS handshake happens before the stream reaches Hyper's auto builder, so ALPN negotiation and HTTP version detection work together transparently.
- Certificates are generated at cluster bootstrap time by the `openshell-bootstrap` crate using `rcgen`, not by a Helm Job. The bootstrap reconciles three K8s secrets: `openshell-server-tls` (server cert+key), `openshell-server-client-ca` (CA cert), and `openshell-client-tls` (client cert+key+CA, shared by CLI and sandbox pods).
- **Certificate lifetime**: Certificates use `rcgen` defaults (effectively never expire), which is appropriate for an internal dev-cluster PKI where certs are ephemeral to the cluster's lifetime.
- **Redeploy behavior**: On redeploy, existing cluster TLS secrets are loaded and reused if they are complete and valid PEM. If secrets are missing, incomplete, or malformed, fresh PKI is generated. If rotation occurs and the openshell workload is already running, the bootstrap performs a rollout restart and waits for completion before persisting CLI-side credentials.

## gRPC Services

### OpenShell Service

Defined in `proto/openshell.proto`, implemented in `crates/openshell-server/src/grpc.rs` as `OpenShellService`.

#### Sandbox Management

| RPC | Description | Key behavior |
|-----|-------------|--------------|
| `Health` | Returns service status and version | Always returns `HEALTHY` with `CARGO_PKG_VERSION` |
| `CreateSandbox` | Create a new sandbox | Validates spec and policy, validates provider names exist (fail-fast), persists to store, creates Kubernetes CRD. On K8s 409 conflict or error, rolls back the store record and index entry. |
| `GetSandbox` | Fetch sandbox by name | Looks up by name via `store.get_message_by_name()` |
| `ListSandboxes` | List sandboxes | Paginated (default limit 100), decodes protobuf payloads from store records |
| `DeleteSandbox` | Delete sandbox by name | Sets phase to `Deleting`, persists, notifies watch bus, then deletes the Kubernetes CRD. Cleans up store if the CRD was already gone. |
| `WatchSandbox` | Stream sandbox updates | Server-streaming RPC. See [Watch Sandbox Stream](#watch-sandbox-stream) below. |
| `ExecSandbox` | Execute command in sandbox | Server-streaming RPC. See [Remote Exec via SSH](#remote-exec-via-ssh) below. |

#### SSH Session Management

| RPC | Description |
|-----|-------------|
| `CreateSshSession` | Creates a session token for a `Ready` sandbox. Persists an `SshSession` record and returns gateway connection details (host, port, scheme, connect path). |
| `RevokeSshSession` | Marks a session as revoked by setting `session.revoked = true` in the store. |

#### Provider Management

Full CRUD for `Provider` objects, which store typed credentials (e.g., API keys for Claude, GitLab tokens).

| RPC | Description |
|-----|-------------|
| `CreateProvider` | Creates a provider. Requires `type` field; auto-generates a 6-char name if not provided. Rejects duplicates by name. |
| `GetProvider` | Fetches a provider by name. |
| `ListProviders` | Paginated list (default limit 100). |
| `UpdateProvider` | Updates an existing provider by name. Preserves the stored `id` and `name`; replaces `type`, `credentials`, and `config`. |
| `DeleteProvider` | Deletes a provider by name. Returns `deleted: true/false`. |

#### Policy, Settings, and Provider Environment Delivery

These RPCs are called by sandbox pods at startup and during runtime polling.

| RPC | Description |
|-----|-------------|
| `GetSandboxSettings` | Returns effective sandbox config looked up by sandbox ID: policy payload, policy metadata (version, hash, source, `global_policy_version`), merged effective settings, and a `config_revision` fingerprint for change detection. Two-tier resolution: registered keys start unset, sandbox values overlay, global values override. The reserved `policy` key in global settings can override the sandbox's own policy. When a global policy is active, `policy_source` is `GLOBAL` and `global_policy_version` carries the active revision number. See [Gateway Settings Channel](gateway-settings.md). |
| `GetGatewaySettings` | Returns gateway-global settings only (excluding the reserved `policy` key). Returns registered keys with empty values when unconfigured, and a monotonic `settings_revision`. |
| `GetSandboxProviderEnvironment` | Resolves provider credentials into environment variables for a sandbox. Iterates the sandbox's `spec.providers` list, fetches each `Provider`, and collects credential key-value pairs. First provider wins on duplicate keys. Skips credential keys that do not match `^[A-Za-z_][A-Za-z0-9_]*$`. |

#### Policy Recommendation (Network Rules)

These RPCs support the sandbox-initiated policy recommendation pipeline. The sandbox generates proposals via its mechanistic mapper and submits them; the gateway validates, persists, and manages the approval workflow. See [architecture/policy-advisor.md](policy-advisor.md) for the full pipeline design.

| RPC | Description |
|-----|-------------|
| `SubmitPolicyAnalysis` | Receives pre-formed `PolicyChunk` proposals from a sandbox. Validates each chunk, persists via upsert on `(sandbox_id, host, port, binary)` dedup key, notifies watch bus. |
| `GetDraftPolicy` | Returns all draft chunks for a sandbox with current draft version. |
| `ApproveDraftChunk` | Approves a pending or rejected chunk. Merges the proposed rule into the active policy (appends binary to existing rule or inserts new rule). **Blocked when a global policy is active** -- returns `FailedPrecondition`. |
| `RejectDraftChunk` | Rejects a pending chunk or revokes an approved chunk. If revoking, removes the binary from the active policy rule. Rejection of `pending` chunks is always allowed. **Revoking approved chunks is blocked when a global policy is active** -- returns `FailedPrecondition`. |
| `ApproveAllDraftChunks` | Bulk approves all pending chunks for a sandbox. **Blocked when a global policy is active** -- returns `FailedPrecondition`. |
| `EditDraftChunk` | Updates the proposed rule on a pending chunk. |
| `GetDraftHistory` | Returns all chunks (including rejected) for audit trail. |

### Inference Service

Defined in `proto/inference.proto`, implemented in `crates/openshell-server/src/inference.rs` as `InferenceService`.

The gateway acts as the control plane for inference configuration. It stores a single managed cluster inference route (named `inference.local`) and delivers resolved route bundles to sandbox pods. The gateway does not execute inference requests -- sandboxes connect directly to inference backends using the credentials and endpoints provided in the bundle.

#### Cluster Inference Configuration

The gateway manages a single cluster-wide inference route that maps to a provider record. When set, the route stores only a `provider_name` and `model_id` reference. At bundle resolution time, the gateway looks up the referenced provider and derives the endpoint URL, API key, protocols, and provider type from it. This late-binding design means provider credential rotations are automatically reflected in the next bundle fetch without updating the route itself.

| RPC | Description |
|-----|-------------|
| `SetClusterInference` | Configures the cluster inference route. Validates `provider_name` and `model_id` are non-empty, verifies the named provider exists and has a supported type for inference (openai, anthropic, nvidia), validates the provider has a usable API key, then upserts the `inference.local` route record. Increments a monotonic `version` on each update. Returns the configured `provider_name`, `model_id`, and `version`. |
| `GetClusterInference` | Returns the current cluster inference configuration (`provider_name`, `model_id`, `version`). Returns `NotFound` if no cluster inference is configured, or `FailedPrecondition` if the stored route has empty provider/model metadata. |
| `GetInferenceBundle` | Returns the resolved inference route bundle for sandbox consumption. See [Route Bundle Delivery](#route-bundle-delivery) below. |

#### Route Bundle Delivery

The `GetInferenceBundle` RPC resolves the managed cluster route into a `GetInferenceBundleResponse` containing fully materialized route data that sandboxes can use directly.

The trait method delegates to `resolve_inference_bundle(store)` (`crates/openshell-server/src/inference.rs`), which takes `&Store` instead of `&self`. This extraction decouples bundle resolution from `ServerState`, enabling direct unit testing against an in-memory SQLite store without constructing a full server.

The `GetInferenceBundleResponse` includes:

- **`routes`** -- a list of `ResolvedRoute` messages containing base URL, model ID, API key, protocols, and provider type. Currently contains zero or one routes (the managed cluster route).
- **`revision`** -- a hex-encoded hash computed from route contents. Sandboxes compare this value to detect when their route set has changed.
- **`generated_at_ms`** -- epoch milliseconds when the bundle was assembled.

#### Provider-Based Route Resolution

Managed route resolution in `resolve_managed_cluster_route()` (`crates/openshell-server/src/inference.rs`):

1. Load the managed route by name (`inference.local`).
2. Skip (return `None`) if the route does not exist, has no spec, or is disabled.
3. Validate that `provider_name` and `model_id` are non-empty.
4. Fetch the referenced provider record from the store.
5. Resolve the provider into a `ResolvedProviderRoute` via `resolve_provider_route()`:
   - Look up the `InferenceProviderProfile` for the provider's type via `openshell_core::inference::profile_for()`. Supported types: `openai`, `anthropic`, `nvidia`.
   - Search the provider's credentials map for an API key using the profile's preferred key name (e.g., `OPENAI_API_KEY`), falling back to the first non-empty credential in sorted key order.
   - Resolve the base URL from the provider's config map using the profile-specific key (e.g., `OPENAI_BASE_URL`), falling back to the profile's default URL.
   - Derive protocols from the profile (e.g., `openai_chat_completions`, `openai_completions`, `openai_responses`, `model_discovery` for OpenAI-compatible providers).
6. Return a `ResolvedRoute` with the fully materialized endpoint, credentials, and protocols.

The `ClusterInferenceConfig` stored in the database contains only `provider_name` and `model_id`. All other fields (endpoint, credentials, protocols, auth style) are resolved from the provider record at bundle generation time via `build_cluster_inference_config()`.

## HTTP Endpoints

The HTTP router (`crates/openshell-server/src/http.rs`) merges two sub-routers:

### Health Endpoints

| Path | Method | Response |
|------|--------|----------|
| `/health` | GET | `200 OK` (empty body) |
| `/healthz` | GET | `200 OK` (empty body) -- Kubernetes liveness probe |
| `/readyz` | GET | `200 OK` with JSON `{"status": "healthy", "version": "<version>"}` -- Kubernetes readiness probe |

### SSH Tunnel Endpoint

| Path | Method | Response |
|------|--------|----------|
| `/connect/ssh` | CONNECT | Upgrades the connection to a bidirectional TCP tunnel to a sandbox pod's SSH port |

See [SSH Tunnel Gateway](#ssh-tunnel-gateway) for details.

### Cloudflare Endpoints

| Path | Method | Response |
|------|--------|----------|
| `/auth/connect` | GET | Browser login relay page that reads `CF_Authorization` and POSTs it back to the CLI localhost callback |
| `/_ws_tunnel` | GET upgrade | WebSocket tunnel that bridges bytes directly into `MultiplexedService` over an in-memory duplex stream |

## Watch Sandbox Stream

The `WatchSandbox` RPC (`crates/openshell-server/src/grpc.rs`) provides a multiplexed server-streaming response that can include sandbox status snapshots, gateway log lines, and platform events.

### Request Options

The `WatchSandboxRequest` controls what the stream includes:

- `follow_status` -- subscribe to `SandboxWatchBus` notifications and re-read the sandbox record on each change.
- `follow_logs` -- subscribe to `TracingLogBus` for gateway log lines correlated by `sandbox_id`.
- `follow_events` -- subscribe to `PlatformEventBus` for Kubernetes events correlated to the sandbox.
- `log_tail_lines` -- replay the last N log lines before following (default 200).
- `stop_on_terminal` -- end the stream when the sandbox reaches the `Ready` phase. Note: `Error` phase does not stop the stream because it may be transient (e.g., `ReconcilerError`).

### Stream Protocol

1. Subscribe to all requested buses **before** reading the initial snapshot (prevents missed notifications).
2. Send the current sandbox record as the first event.
3. If `stop_on_terminal` is set and the sandbox is already `Ready`, end the stream immediately.
4. Replay tail logs if `follow_logs` is enabled.
5. Enter a `tokio::select!` loop listening on up to three broadcast receivers:
   - **Status updates**: re-read the sandbox from the store, send the snapshot, check for terminal phase.
   - **Log lines**: forward `SandboxStreamEvent::Log` messages.
   - **Platform events**: forward `SandboxStreamEvent::Event` messages.

### Event Bus Architecture

```mermaid
graph LR
    SW["spawn_sandbox_watcher"]
    ET["spawn_kube_event_tailer"]
    TL["SandboxLogLayer<br/>(tracing layer)"]

    WB["SandboxWatchBus<br/>(broadcast per ID)"]
    LB["TracingLogBus<br/>(broadcast per ID + tail buffer)"]
    PB["PlatformEventBus<br/>(broadcast per ID)"]

    WS["WatchSandbox stream"]

    SW -->|"notify(id)"| WB
    TL -->|"publish(id, log_event)"| LB
    ET -->|"publish(id, platform_event)"| PB

    WB -->|"subscribe(id)"| WS
    LB -->|"subscribe(id)"| WS
    PB -->|"subscribe(id)"| WS
```

All buses use `tokio::sync::broadcast` channels keyed by sandbox ID. Buffer sizes:
- `SandboxWatchBus`: 128 (signals only, no payload -- just `()`)
- `TracingLogBus`: 1024 (full `SandboxStreamEvent` payloads)
- `PlatformEventBus`: 1024 (full `SandboxStreamEvent` payloads)

Broadcast lag is translated to `Status::resource_exhausted` via `broadcast_to_status()`.

**Cleanup:** Each bus exposes a `remove(sandbox_id)` method that drops the broadcast sender (closing active receivers with `RecvError::Closed`) and frees internal map entries. Cleanup is wired into the compute watch reconciler, the periodic snapshot reconcile for sandboxes missing from the driver, and the `delete_sandbox` gRPC handler to prevent unbounded memory growth from accumulated entries for deleted sandboxes.

**Validation:** `WatchSandbox` validates that the sandbox exists before subscribing to any bus, preventing entries from being created for non-existent IDs. `PushSandboxLogs` validates sandbox existence once on the first batch of the stream.

## Remote Exec via SSH

The `ExecSandbox` RPC (`crates/openshell-server/src/grpc.rs`) executes a command inside a sandbox pod over SSH and streams stdout/stderr/exit back to the client.

### Execution Flow

1. Validate request: `sandbox_id`, `command`, and environment key format (`^[A-Za-z_][A-Za-z0-9_]*$`).
2. Verify sandbox exists and is in `Ready` phase.
3. Resolve target: prefer agent pod IP, fall back to Kubernetes service DNS (`<name>.<namespace>.svc.cluster.local`). If the sandbox is not connectable yet (for example the pod exists but has no IP), the gateway returns `FAILED_PRECONDITION` instead of surfacing the condition as an internal server fault.
4. Build the remote command string: sort environment variables, shell-escape all values, prepend `cd <workdir> &&` if `workdir` is set.
5. **Start a single-use SSH proxy**: binds an ephemeral local TCP port, accepts one connection, performs the NSSH1 handshake with the sandbox, and bidirectionally copies data.
6. **Connect via `russh`**: establishes an SSH connection through the local proxy, authenticates with `none` auth as user `sandbox`, opens a session channel, and executes the command.
7. Stream `ExecSandboxStdout`, `ExecSandboxStderr` chunks as they arrive, then send `ExecSandboxExit` with the exit code.
8. On timeout (if `timeout_seconds > 0`), send exit code 124 (matching the `timeout(1)` convention).

### NSSH1 Handshake Protocol

The single-use SSH proxy and the SSH tunnel endpoint both use the same handshake:

```
NSSH1 <token> <timestamp> <nonce> <hmac_signature>\n
```

- `token` -- session token or a one-time UUID.
- `timestamp` -- Unix epoch seconds.
- `nonce` -- UUID v4.
- `hmac_signature` -- `HMAC-SHA256(secret, "{token}|{timestamp}|{nonce}")`, hex-encoded.
- Expected response: `OK\n` from the sandbox.

The `ssh_handshake_skew_secs` configuration controls how much clock skew is tolerated.

## SSH Tunnel Gateway

The SSH tunnel endpoint (`crates/openshell-server/src/ssh_tunnel.rs`) allows external SSH clients to reach sandbox pods through the gateway using HTTP CONNECT upgrades.

### Request Flow

1. Client sends `CONNECT /connect/ssh` with headers `x-sandbox-id` and `x-sandbox-token`.
2. Handler validates the method is CONNECT, extracts headers.
3. Fetches the `SshSession` from the store by token; rejects if revoked or if `sandbox_id` does not match.
4. Fetches the `Sandbox`; rejects if not in `Ready` phase.
5. Resolves the connect target: agent pod IP if available, otherwise Kubernetes service DNS.
6. Returns `200 OK`, then upgrades the connection via `hyper::upgrade::on()`.
7. In a spawned task: connects to the sandbox's SSH port, performs the NSSH1 handshake, then bidirectionally copies bytes between the upgraded HTTP connection and the sandbox TCP stream.
8. On completion, gracefully shuts down the write-half of the upgraded connection for clean EOF handling.

## Persistence Layer

### Store Architecture

The `Store` enum (`crates/openshell-server/src/persistence/mod.rs`) dispatches to either `SqliteStore` or `PostgresStore` based on the database URL prefix:

- `sqlite:*` -- uses `sqlx::SqlitePool` (1 connection for in-memory, 5 for file-based).
- `postgres://` or `postgresql://` -- uses `sqlx::PgPool` (max 10 connections).

Both backends auto-run migrations on connect from `crates/openshell-server/migrations/{sqlite,postgres}/`.

### Schema

A single `objects` table stores all object types:

```sql
CREATE TABLE objects (
    object_type TEXT NOT NULL,
    id          TEXT NOT NULL,
    name        TEXT NOT NULL,
    payload     BLOB NOT NULL,
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    PRIMARY KEY (id),
    UNIQUE (object_type, name)
);
```

Objects are identified by `(object_type, id)` with a unique constraint on `(object_type, name)`. The `payload` column stores protobuf-encoded bytes.

### Object Types

| Object type string | Proto message / format | Traits implemented | Notes |
|--------------------|------------------------|-------------------|-------|
| `"sandbox"` | `Sandbox` | `ObjectType`, `ObjectId`, `ObjectName` | |
| `"provider"` | `Provider` | `ObjectType`, `ObjectId`, `ObjectName` | |
| `"ssh_session"` | `SshSession` | `ObjectType`, `ObjectId`, `ObjectName` | |
| `"inference_route"` | `InferenceRoute` | `ObjectType`, `ObjectId`, `ObjectName` | |
| `"gateway_settings"` | JSON `StoredSettings` | Generic `put`/`get` | Singleton, id=`"global"`. Contains the reserved `policy` key for global policy delivery. |
| `"sandbox_settings"` | JSON `StoredSettings` | Generic `put`/`get` | Per-sandbox, id=`"settings:{sandbox_uuid}"` |

The `sandbox_policies` table stores versioned policy revisions for both sandbox-scoped and global policies. Global revisions use the sentinel `sandbox_id = "__global__"`. See [Gateway Settings Channel](gateway-settings.md#storage-model) for schema details.

### Generic Protobuf Codec

The `Store` provides typed helpers that leverage trait bounds:

- `put_message<T: Message + ObjectType + ObjectId + ObjectName>(&self, msg: &T)` -- encodes to protobuf bytes and upserts.
- `get_message<T: Message + Default + ObjectType>(&self, id: &str)` -- fetches by ID, decodes protobuf.
- `get_message_by_name<T: Message + Default + ObjectType>(&self, name: &str)` -- fetches by name, decodes protobuf.

The `generate_name()` function produces random 6-character lowercase alphabetic strings for auto-naming objects.

### Deployment Storage

The gateway runs as a Kubernetes **StatefulSet** with a `volumeClaimTemplate` that provisions a 1Gi `ReadWriteOnce` PersistentVolumeClaim mounted at `/var/openshell`. On k3s clusters this uses the built-in `local-path-provisioner` StorageClass (the cluster default). The SQLite database file at `/var/openshell/openshell.db` survives pod restarts and rescheduling.

The Helm chart template is at `deploy/helm/openshell/templates/statefulset.yaml`.

### CRUD Semantics

- **Put**: Performs an upsert (`INSERT ... ON CONFLICT (id) DO UPDATE ...`). Both `created_at_ms` and `updated_at_ms` are set to the current timestamp in the `VALUES` clause, but the `ON CONFLICT` update only writes `payload` and `updated_at_ms` -- so `created_at_ms` is preserved after the initial insert.
- **Get / Delete**: Operate by primary key (`id`), filtered by `object_type`.
- **List**: Pages by `limit` + `offset` with deterministic ordering: `ORDER BY created_at_ms ASC, name ASC`. The secondary sort on `name` prevents unstable ordering when rows share the same millisecond timestamp.

## Kubernetes Integration

### Sandbox CRD Management

`KubernetesComputeDriver` (`crates/openshell-driver-kubernetes/src/driver.rs`) manages `agents.x-k8s.io/v1alpha1/Sandbox` CRDs behind the gateway's compute interface. The gateway binds to that driver through `ComputeDriverService` (`crates/openshell-driver-kubernetes/src/grpc.rs`) in-process, so the same `openshell.compute.v1.ComputeDriver` request and response types are exercised whether the driver is invoked locally or served over gRPC.

- **Get**: `GetSandbox` looks up a sandbox CRD by name and returns a driver-native platform observation (`openshell.compute.v1.DriverSandbox`) with raw status and condition data from the object.
- **List**: `ListSandboxes` enumerates sandbox CRDs and returns driver-native platform observations for each, sorted by name for stable results.
- **Create**: Translates an internal `openshell.compute.v1.DriverSandbox` message into a Kubernetes `DynamicObject` with labels (`openshell.ai/sandbox-id`, `openshell.ai/managed-by: openshell`) and a spec that includes the pod template, environment variables, and gateway-required env vars (`OPENSHELL_SANDBOX_ID`, `OPENSHELL_ENDPOINT`, `OPENSHELL_SSH_LISTEN_ADDR`, etc.). When callers do not provide custom `volumeClaimTemplates`, the driver injects a default `workspace` PVC and mounts it at `/sandbox` so the default sandbox home/workdir survives pod rescheduling.
- **Delete**: Calls the Kubernetes API to delete the CRD by name. Returns `false` if already gone (404).
- **Stop**: `proto/compute_driver.proto` now reserves `StopSandbox` for a non-destructive lifecycle transition. Resume is intentionally not a dedicated compute-driver RPC; the gateway is expected to auto-resume a stopped sandbox when a client connects or executes into it.
- **Pod IP resolution**: `agent_pod_ip()` fetches the agent pod and reads `status.podIP`.

### Sandbox Watcher

The Kubernetes driver emits `WatchSandboxes` events through `proto/compute_driver.proto`. `ComputeRuntime` consumes that stream, translates the driver-native snapshots into public `openshell.v1.Sandbox` resources, derives the public phase, and applies the results to the store.

- **Applied**: Extracts the sandbox ID from labels (or falls back to name prefix stripping), reads the CRD status, emits a driver-native snapshot, and lets the gateway translate that into the stored public sandbox record. Notifies the watch bus.
- **Deleted**: Removes the sandbox record from the store and the index. Notifies the watch bus.
- **Restarted**: Re-processes all objects (full resync).

In addition to the watch stream, `ComputeRuntime` periodically calls `ComputeDriver/ListSandboxes` through the in-process `ComputeDriverService` and reconciles the store to that full driver snapshot. Public `GetSandbox` and `ListSandboxes` handlers remain store-backed, but the store is refreshed from the driver on a timer so the gateway still exercises the compute-driver RPC surface for reconciliation.

### Gateway Phase Derivation

`ComputeRuntime::derive_phase()` (`crates/openshell-server/src/compute/mod.rs`) maps driver-native compute status to the public `SandboxPhase` exposed by `proto/openshell.proto`:

| Condition | Phase |
|-----------|-------|
| Driver status `deleting=true` | `Deleting` |
| Ready condition `status=True` | `Ready` |
| Ready condition `status=False`, terminal reason | `Error` |
| Ready condition `status=False`, transient reason | `Provisioning` |
| No conditions or no status | `Provisioning` (if status exists) / `Unknown` (if no status) |

**Transient reasons** (will retry, stay in `Provisioning`): `ReconcilerError`, `DependenciesNotReady`.
All other `Ready=False` reasons are treated as terminal failures (`Error` phase).

### Kubernetes Event Tailer

The Kubernetes driver also watches namespace-scoped Kubernetes `Event` objects and correlates them to sandbox IDs before emitting them as compute-driver platform events:

- Events involving `kind: Sandbox` are correlated by sandbox name.
- Events involving `kind: Pod` are correlated by agent pod name.
- Other event kinds are ignored.

Matched events are published to the `PlatformEventBus` as `SandboxStreamEvent::Event` payloads.

## VM Driver

`VmDriver` (`crates/openshell-driver-vm/src/driver.rs`) is served by the standalone `openshell-driver-vm` process. The gateway spawns that binary on demand, talks to it over the internal `openshell.compute.v1.ComputeDriver` gRPC contract via a Unix domain socket, and keeps VM runtime dependencies out of `openshell-server`.

- **Create**: The VM driver process allocates a localhost SSH port, prepares a sandbox-specific rootfs from its own embedded `rootfs.tar.zst`, injects an explicitly configured guest mTLS bundle when the gateway callback endpoint is `https://`, then re-execs itself in a hidden helper mode that loads libkrun directly and boots `/srv/openshell-vm-sandbox-init.sh`.
- **Networking**: The helper starts an embedded `gvproxy`, wires it into libkrun as virtio-net, and exposes the single inbound SSH port (`host_port:2222`) through gvproxy’s forwarder API. This keeps VM launch inside `openshell-driver-vm` without depending on the `openshell-vm` binary.
- **Gateway callback**: The guest init script configures `eth0` for gvproxy networking, prefers the configured `OPENSHELL_GRPC_ENDPOINT`, and falls back to host aliases or the gvproxy gateway IP (`192.168.127.1`) when local hostname resolution is unavailable on macOS.
- **Guest boot**: The sandbox guest runs a minimal init script that skips k3s and starts `openshell-sandbox` directly as PID 1 inside the VM.
- **Endpoint resolution**: Returns `127.0.0.1:<allocated-port>` for SSH/exec transport.
- **Watch stream**: Emits provisioning, ready, error, deleting, deleted, and platform-event updates so the gateway store remains the durable source of truth.

## Sandbox Index

`SandboxIndex` (`crates/openshell-server/src/sandbox_index.rs`) maintains two in-memory maps protected by an `RwLock`:

- `sandbox_name_to_id: HashMap<String, String>`
- `agent_pod_to_id: HashMap<String, String>`

Updated by the sandbox watcher on every Applied event and by gRPC handlers during sandbox creation. Used by the event tailer to map Kubernetes event objects back to sandbox IDs.

## Error Handling

- **gRPC errors**: All gRPC handlers return `tonic::Status` with appropriate codes:
  - `InvalidArgument` for missing/malformed fields
  - `NotFound` for nonexistent objects
  - `AlreadyExists` for duplicate creation
  - `FailedPrecondition` for state violations (e.g., exec on non-Ready sandbox, missing provider)
  - `Internal` for store/decode/Kubernetes failures
  - `PermissionDenied` for policy violations
  - `ResourceExhausted` for broadcast lag (missed messages)
  - `Cancelled` for closed broadcast channels

- **HTTP errors**: The SSH tunnel handler returns HTTP status codes directly (`401`, `404`, `405`, `412`, `500`, `502`).

- **Connection errors**: Logged at `error` level but do not crash the gateway. TLS handshake failures and individual connection errors are caught and logged per-connection.

- **Background task errors**: The sandbox watcher and event tailer log warnings for individual processing failures but continue running. If the watcher stream ends, it logs a warning and the task exits (no automatic restart).

## Cross-References

- [Sandbox Architecture](sandbox.md) -- sandbox-side policy enforcement, proxy, and isolation details
- [Gateway Settings Channel](gateway-settings.md) -- runtime settings channel, two-tier resolution, CLI/TUI commands
- [Inference Routing](inference-routing.md) -- end-to-end inference interception flow, sandbox-side proxy logic, and route resolution
- [Container Management](build-containers.md) -- how sandbox container images are built and configured
- [Sandbox Connect](sandbox-connect.md) -- client-side SSH connection flow
- [Providers](sandbox-providers.md) -- provider credential management and injection
