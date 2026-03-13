# Principal Engineer Reviewer Memory

## Project Structure
- Proto definitions: `proto/openshell.proto`, `proto/sandbox.proto`, `proto/sandbox_policy.proto`
- Server gRPC handlers: `crates/openshell-server/src/grpc.rs`
- TracingLogBus (log broadcast): `crates/openshell-server/src/tracing_bus.rs`
- Sandbox watch bus: `crates/openshell-server/src/sandbox_watch.rs`
- Server state: `crates/openshell-server/src/lib.rs` (ServerState struct)
- Sandbox main: `crates/openshell-sandbox/src/main.rs`
- Sandbox library: `crates/openshell-sandbox/src/lib.rs`
- Sandbox gRPC client: `crates/openshell-sandbox/src/grpc_client.rs`
- CLI commands: `crates/openshell-cli/src/main.rs` (clap defs), `crates/openshell-cli/src/run.rs` (impl)
- Python SDK: `python/openshell/`
- Plans go in: `architecture/plans/`

## Key Patterns
- TracingLogBus: per-sandbox broadcast::channel(1024) + VecDeque tail buffer (200 lines)
- CachedOpenShellClient: reusable mTLS gRPC channel for sandbox->server calls
- SandboxLogLayer: tracing Layer that captures events with sandbox_id field
- Sandbox logging: stdout (ANSI, configurable level) + /var/log/openshell.log (info, no ANSI, non-blocking)
- WatchSandbox: server-streaming with select! loop over status_rx, log_rx, platform_rx
- Proto codegen: `mise run proto`
- Build: `mise run sandbox` for sandbox infra

## Review Preferences (observed)
- Plans stored as markdown in architecture/plans/
- Conventional commits required
- No AI attribution in commits
