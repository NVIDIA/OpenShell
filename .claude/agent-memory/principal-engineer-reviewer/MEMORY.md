# Principal Engineer Reviewer Memory

## Project Structure
- Proto definitions: `proto/ryno.proto`, `proto/sandbox.proto`, `proto/sandbox_policy.proto`
- Server gRPC handlers: `crates/ryno-server/src/grpc.rs`
- TracingLogBus (log broadcast): `crates/ryno-server/src/tracing_bus.rs`
- Sandbox watch bus: `crates/ryno-server/src/sandbox_watch.rs`
- Server state: `crates/ryno-server/src/lib.rs` (ServerState struct)
- Sandbox main: `crates/ryno-sandbox/src/main.rs`
- Sandbox library: `crates/ryno-sandbox/src/lib.rs`
- Sandbox gRPC client: `crates/ryno-sandbox/src/grpc_client.rs`
- CLI commands: `crates/ryno-cli/src/main.rs` (clap defs), `crates/ryno-cli/src/run.rs` (impl)
- Python SDK: `python/ryno/`
- Plans go in: `plans/`

## Key Patterns
- TracingLogBus: per-sandbox broadcast::channel(1024) + VecDeque tail buffer (200 lines)
- CachedRynoClient: reusable mTLS gRPC channel for sandbox->server calls
- SandboxLogLayer: tracing Layer that captures events with sandbox_id field
- Sandbox logging: stdout (ANSI, configurable level) + /var/log/ryno.log (info, no ANSI, non-blocking)
- WatchSandbox: server-streaming with select! loop over status_rx, log_rx, platform_rx
- Proto codegen: `mise run proto`
- Build: `mise run sandbox` for sandbox infra

## Review Preferences (observed)
- Plans stored as markdown in plans/
- Conventional commits required
- No AI attribution in commits
