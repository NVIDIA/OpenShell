# Principal Engineer Reviewer Memory

## Project Structure
- Proto definitions: `proto/navigator.proto`, `proto/sandbox.proto`, `proto/sandbox_policy.proto`
- Server gRPC handlers: `crates/navigator-server/src/grpc.rs`
- TracingLogBus (log broadcast): `crates/navigator-server/src/tracing_bus.rs`
- Sandbox watch bus: `crates/navigator-server/src/sandbox_watch.rs`
- Server state: `crates/navigator-server/src/lib.rs` (ServerState struct)
- Sandbox main: `crates/navigator-sandbox/src/main.rs`
- Sandbox library: `crates/navigator-sandbox/src/lib.rs`
- Sandbox gRPC client: `crates/navigator-sandbox/src/grpc_client.rs`
- CLI commands: `crates/navigator-cli/src/main.rs` (clap defs), `crates/navigator-cli/src/run.rs` (impl)
- Python SDK: `python/navigator/`
- Plans go in: `architecture/plans/`

## Key Patterns
- TracingLogBus: per-sandbox broadcast::channel(1024) + VecDeque tail buffer (200 lines)
- CachedNavigatorClient: reusable mTLS gRPC channel for sandbox->server calls
- SandboxLogLayer: tracing Layer that captures events with sandbox_id field
- Sandbox logging: stdout (ANSI, configurable level) + /var/log/navigator.log (info, no ANSI, non-blocking)
- WatchSandbox: server-streaming with select! loop over status_rx, log_rx, platform_rx
- Proto codegen: `mise run proto`
- Build: `mise run sandbox` for sandbox infra

## Review Preferences (observed)
- Plans stored as markdown in architecture/plans/
- Conventional commits required
- No AI attribution in commits
