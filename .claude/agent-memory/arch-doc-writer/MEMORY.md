# Arch Doc Writer Memory

## Project Structure
- Crates: `navigator-cli`, `navigator-server`, `navigator-sandbox`, `navigator-bootstrap`, `navigator-core`, `navigator-providers`, `navigator-router`
- CLI entry: `crates/navigator-cli/src/main.rs` (clap parser + dispatch)
- CLI logic: `crates/navigator-cli/src/run.rs` (all command implementations)
- Sandbox entry: `crates/navigator-sandbox/src/lib.rs` (`run_sandbox()`)
- OPA engine: `crates/navigator-sandbox/src/opa.rs` (single file, not a directory)
- Identity cache: `crates/navigator-sandbox/src/identity.rs` (SHA256 TOFU, uses Mutex<HashMap> NOT DashMap)
- L7 inspection: `crates/navigator-sandbox/src/l7/` (mod.rs, tls.rs, relay.rs, rest.rs, provider.rs, inference.rs)
- Proxy: `crates/navigator-sandbox/src/proxy.rs`
- Server multiplex: `crates/navigator-server/src/multiplex.rs`
- SSH tunnel: `crates/navigator-server/src/ssh_tunnel.rs`
- Sandbox SSH server: `crates/navigator-sandbox/src/ssh.rs`
- Providers: `crates/navigator-providers/src/providers/` (per-provider modules)
- Bootstrap: `crates/navigator-bootstrap/src/lib.rs` (cluster lifecycle)
- Proto files: `proto/` directory (navigator.proto, sandbox.proto, datamodel.proto)

## Architecture Docs
- Files renamed from numbered prefix format to descriptive names (e.g., `2 - server-architecture.md` -> `gateway-architecture.md`)
- Current files: README.md, sandbox-providers.md, cluster-single-node.md, build-containers.md, sandbox-connect.md, sandbox.md, security-policy.md, gateway.md, gateway-security.md, sandbox-custom-containers.md, inference-routing.md
- Cross-references use plain filenames: `[text](gateway.md)`
- Naming convention: "gateway" in prose for the control plane component; code identifiers like `navigator-server` stay unchanged

## Key Patterns
- OPA baked-in rules: `include_str!("../../../dev-sandbox-policy.rego")` in opa.rs
- Policy loading: gRPC mode (NAVIGATOR_SANDBOX_ID + NAVIGATOR_ENDPOINT) or file mode (--policy-rules + --policy-data)
- Provider env injection: both entrypoint process (tokio Command) and SSH shell (std Command)
- Cluster bootstrap: `sandbox_create_with_bootstrap()` auto-deploys when no cluster exists (main.rs ~line 632)
- CLI cluster resolution: --cluster flag > NAVIGATOR_CLUSTER env > active cluster file

## Bootstrap Crate Details
- `docker.rs`: `ensure_container()` sets ~12 env vars (REGISTRY_*, IMAGE_*, PUSH_IMAGE_REFS, etc.)
- `runtime.rs`: Polling params: kubeconfig 30x2s, health 180x2s, mTLS 90x2s
- `metadata.rs`: Metadata at `clusters/{name}_metadata.json` (flat), kubeconfig/mTLS at `clusters/{name}/` (nested)
- `push.rs`: Uses `ctr` (not `k3s ctr`) with k3s containerd socket, `k8s.io` namespace
- IMPORTANT: `ClusterHandle::destroy()` does NOT remove metadata; only CLI `cluster_admin_destroy()` in run.rs does
- `ensure_image()`: Local-only refs (no `/`) get error with build instructions, not a Docker Hub pull attempt
- Dockerfile.cluster: k3s v1.29.8-k3s1 base, manifests in `/opt/navigator/manifests/` (volume mount overwrites `/var/lib/`)
- Healthcheck: checks k8s readyz, StatefulSet ready, Gateway Programmed, conditionally mTLS secret

## Server Crate Details
- Two gRPC services: Navigator (grpc.rs) and Inference (inference.rs), multiplexed via GrpcRouter by URI path
- Gateway is control-plane only for inference: route CRUD + GetSandboxInferenceBundle
- GetSandboxInferenceBundle: returns SandboxResolvedRoute list + revision hash + generated_at_ms for a sandbox_id
- Persistence: single `objects` table, protobuf payloads, Store enum dispatches SQLite vs Postgres by URL prefix
- Persistence CRUD: upsert ON CONFLICT (id) not (object_type, id); list ORDER BY created_at_ms ASC, name ASC (not id!)
- --db-url has no code default; Helm values.yaml sets `sqlite:/var/navigator/navigator.db`
- Object types: "sandbox", "provider", "ssh_session", "inference_route" -- each implements ObjectType/ObjectId/ObjectName
- Config: `navigator_core::Config` in `crates/navigator-core/src/config.rs`, all flags have env var fallbacks
- SSH handshake: "NSSH1" preface + HMAC-SHA256, used in both exec proxy (grpc.rs) and tunnel gateway (ssh_tunnel.rs)
- Phase derivation: transient reasons (ReconcilerError, DependenciesNotReady) -> Provisioning; all others -> Error
- Broadcast bus buffer sizes: SandboxWatchBus=128, TracingLogBus=1024, PlatformEventBus=1024
- Sandbox CRD: `agents.x-k8s.io/v1alpha1/Sandbox`, labels: `navigator.ai/sandbox-id`, `navigator.ai/managed-by`
- Proto files also include: `proto/inference.proto` (navigator.inference.v1)

## Container/Build Details
- Four runtime images: sandbox (5 stages), server (2 stages), cluster (k3s base), pki-job (Alpine)
- Two build-only images: python-wheels (Linux multi-arch), python-wheels-macos (osxcross cross-compile)
- CI image: Dockerfile.ci (Ubuntu 24.04, pre-installs docker/buildx/aws/kubectl/helm/mise/uv/sccache/socat)
- Cross-compilation: `deploy/docker/cross-build.sh` shared by sandbox + server Dockerfiles
- Sandbox image has coding-agents stage: Claude CLI (native installer), OpenCode, Codex (npm)
- Helm chart deploys a StatefulSet (NOT Deployment), PVC 1Gi at /var/navigator
- Cluster image does NOT bundle image tarballs -- components pulled at runtime from distribution registry
- PKI job generates CA + server cert + client cert for mTLS (RSA 2048, 10yr, Helm pre-install hook)
- Build tasks in `tasks/*.toml`; scripts in `tasks/scripts/`
- `cluster-deploy-fast.sh` supports both auto mode (git diff) and explicit targets (server/sandbox/pki-job/chart/all)
- `cluster-bootstrap.sh` ensures local Docker registry on port 5000, pushes all components, then deploys
- Default values.yaml: repository is CloudFront-backed CDN, tag: "latest", pullPolicy: Always
- Envoy Gateway version: v1.5.8 (set in mise.toml)
- DNS solution in cluster-entrypoint.sh: iptables DNAT proxy (NOT host-gateway resolv.conf)

## Sandbox Connect Details
- CLI SSH module: `crates/navigator-cli/src/ssh.rs` (sandbox_connect, sandbox_exec, sandbox_rsync, sandbox_ssh_proxy)
- Re-exported from run.rs: `pub use crate::ssh::{...}` for backward compat
- ssh-proxy subcommand: `Commands::SshProxy` in main.rs (~line 139)
- Gateway loopback resolution: `resolve_ssh_gateway()` in ssh.rs -- overrides loopback with cluster endpoint host
- ExecSandbox gRPC: uses single-use TCP proxy + russh client in grpc.rs
- PTY I/O: 3 std::threads (writer, reader, exit) with reader_done sync for SSH protocol ordering
- SSH daemon: russh server, ephemeral Ed25519 key, pre_exec: setsid -> TIOCSCTTY -> setns -> drop_privileges -> sandbox::apply

## Policy Reload Details
- Poll loop: `run_policy_poll_loop()` in lib.rs, spawned after child process, gRPC mode only
- `OpaEngine::reload_from_proto()`: reuses `from_proto()` pipeline, atomically swaps inner engine, LKG on failure
- `CachedNavigatorClient` in grpc_client.rs: persistent mTLS channel for poll + status report (mirrors CachedInferenceClient)
- Dynamic domains: network_policies, inference (OPA engine swap). Static domains: filesystem, landlock, process (pre_exec, immutable)
- Server-side: `UpdateSandboxPolicy` RPC rejects changes to static fields or network mode changes
- Server-side validation: `validate_static_fields_unchanged()` + `validate_network_mode_unchanged()` in grpc.rs
- Poll interval: `NAVIGATOR_POLICY_POLL_INTERVAL_SECS` env var (default 30), no CLI flag
- Version tracking: monotonic i64 per sandbox, `GetSandboxPolicyResponse` has version + policy_hash
- Version 1 backfill: lazy on first `GetSandboxPolicy` from spec.policy if no policy_revisions row exists
- `supersede_pending_policies()`: marks older pending revisions as superseded when new version persisted
- Status reporting: `ReportPolicyStatus` RPC with `PolicyStatus` enum (PENDING, LOADED, FAILED, SUPERSEDED)
- `report_policy_status()` updates `sandbox.current_policy_version` on LOADED, notifies watch bus
- Proto files: `ReportPolicyStatusRequest`/`Response` in navigator.proto, `GetSandboxPolicyResponse` in sandbox.proto
- `Sandbox.current_policy_version` (uint32) in datamodel.proto -- tracks active loaded version
- Persistence: `PolicyRecord` in persistence/mod.rs (id, sandbox_id, version, policy_payload, policy_hash, status, load_error, timestamps)
- CLI: `PolicyCommands` enum in main.rs (~line 516): Set, Get, List subcommands
- CLI: `sandbox_policy_set()` in run.rs (~line 2901): loads YAML, calls UpdateSandboxPolicy, optionally polls for status
- CLI: `sandbox_policy_get()` in run.rs (~line 3015): supports --rev N (version=0 means latest) and --full (YAML output via policy_to_yaml)
- CLI: `sandbox_logs()` in run.rs (~line 3124): --source (all/gateway/sandbox) and --level (error/warn/info/debug/trace) filters
- Deterministic hashing: `deterministic_policy_hash()` in grpc.rs (~line 1133): sorts network_policies by key, hashes fields individually
- Idempotent UpdateSandboxPolicy: compares hash of new policy to latest stored hash, returns existing version if match
- `policy_to_yaml()` in run.rs (~line 1623): converts proto to YAML via `PolicyYaml` struct (uses BTreeMap for ordered keys)
- `policy_record_to_revision()` in grpc.rs (~line 1234): `include_policy` param controls whether full proto is included
- Server-side log filtering: `source_matches()` + `level_matches()` in grpc.rs, applied in both get_sandbox_logs and watch_sandbox
- Standalone `proxy_inference()` was removed; proxy uses `CachedInferenceClient` via `InferenceContext.grpc_client` (OnceCell)

## Policy System Details
- YAML data file top-level keys: filesystem_policy, landlock, process, network_policies, inference
- Proto message field `filesystem` maps to YAML key `filesystem_policy` (different names!)
- Behavioral trigger: network_policies non-empty -> proxy mode, empty -> block mode (seccomp blocks AF_INET/AF_INET6)
- Behavioral trigger: endpoint `protocol` field -> L7 inspection; absent -> L4 raw copy_bidirectional
- Behavioral trigger: `tls: terminate` -> MITM TLS with ephemeral CA; requires `protocol` to also be set
- Behavioral trigger: `enforcement: enforce` -> deny at proxy; `audit` (default) -> log + forward
- Access presets: read-only (GET/HEAD/OPTIONS), read-write (+POST/PUT/PATCH), full (*/*)
- Validation: rules+access mutual exclusion, protocol requires rules/access, sql+enforce blocked, empty rules rejected
- Identity binding: /proc/net/tcp -> inode -> PID -> /proc/PID/exe + ancestors + cmdline, SHA256 TOFU cache
- Network namespace: 10.200.0.1 (host/proxy) <-> 10.200.0.2 (sandbox), port 3128 default
- Enforcement order in pre_exec: setns -> drop_privileges -> landlock -> seccomp
- TLS cert cache: 256 entries max, overflow clears entire map
- CA files: /etc/navigator-tls/navigator-ca.pem (standalone) + ca-bundle.pem (system CAs + sandbox CA)
- Trust env vars: NODE_EXTRA_CA_CERTS, SSL_CERT_FILE, REQUESTS_CA_BUNDLE, CURL_CA_BUNDLE

## Proxy SSRF Protection
- `is_internal_ip()` and `resolve_and_reject_internal()` in proxy.rs
- Blocks: 127/8, 10/8, 172.16/12, 192.168/16, 169.254/16, ::1, fe80::/10, IPv4-mapped IPv6
- Runs after OPA allow, before TcpStream::connect
- Control plane endpoints exempt (they connect via hostname, skip SSRF check)
- DNS failure also rejects the connection
- Non-CP connections use pre-resolved addrs: `TcpStream::connect(addrs.as_slice())`

## Inference Routing Details
- Sandbox-local execution via navigator-router crate
- OPA three-action model: Allow, InspectForInference, Deny (`NetworkAction` in opa.rs)
- InferenceContext: Router + patterns + `Arc<RwLock<Vec<ResolvedRoute>>>` route cache
- Route sources: `--inference-routes` YAML file (standalone) > cluster bundle via gRPC; empty routes gracefully disable
- Cluster bundle refreshed every ROUTE_REFRESH_INTERVAL_SECS (30s)
- Patterns: POST /v1/chat/completions, /v1/completions, /v1/responses, /v1/messages
- Dev sandbox: `mise run sandbox -e VAR_NAME` forwards host env vars; NVIDIA_API_KEY always passed

## Log Streaming Details
- LogPushLayer: `crates/navigator-sandbox/src/log_push.rs` -- tracing layer + spawn_log_push_task()
- Initialized in main.rs before run_sandbox(), gRPC mode only
- mpsc channel: 1024 lines (bounded), try_send (best-effort, never blocks)
- Background task: batches up to 50 lines, flushes every 500ms via PushSandboxLogs client-streaming RPC
- Secondary channel to gRPC call: mpsc::channel::<PushSandboxLogsRequest>(32) wrapped in ReceiverStream
- CachedNavigatorClient.raw_client() returns clone of inner NavigatorClient for direct RPC calls
- NAVIGATOR_LOG_PUSH_LEVEL env var (default INFO), parsed in LogPushLayer::new()
- Server handler: push_sandbox_logs in grpc.rs, caps 100 lines/batch, forces source="sandbox" + sandbox_id
- TracingLogBus.publish_external(): injects into same broadcast + tail buffer as SandboxLogLayer
- Tail buffer: DEFAULT_TAIL = 2000 lines per sandbox (was 200, increased with log push)
- SandboxLogLayer (server tracing layer): sets source="gateway", only publishes events with sandbox_id field
- CLI: --source (gateway/sandbox/all), --level (error/warn/info/debug/trace) on `sandbox logs`
- Source filter: "all" normalized to empty list (no filter) in run.rs
- level_matches(): numeric ranking ERROR=0..TRACE=4, unknown levels always pass
- Create-watch filter: log_sources: ["gateway"] to prevent sandbox logs from blocking stop_on_terminal
- Proto: SandboxLogLine.source (string), SandboxLogLine.fields (map<string,string>)
- Proto: PushSandboxLogsRequest/Response, GetSandboxLogsRequest (sources, min_level fields)
- Proto: WatchSandboxRequest (log_sources, log_min_level fields)

## Naming Conventions
- The project name "Navigator" appears in code but docs should use generic terms per user preference
- CLI binary: `navigator` (aliased as `nav` in dev via mise)
- Provider types: claude, codex, opencode, openclaw, generic, nvidia, gitlab, github, outlook
