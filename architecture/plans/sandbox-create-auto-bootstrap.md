# Sandbox Create Auto-Bootstrap Plan

## Goals

- When `navigator sandbox create` is run and no cluster is reachable, automatically offer cluster bootstrap.
- Require explicit user confirmation before bootstrapping a cluster.
- Support remote bootstrap directly from sandbox create, including:
  - `navigator sandbox create --remote <ssh-host> -- <command>`
- Continue into normal sandbox provisioning immediately after successful bootstrap.

## Non-goals

- No silent auto-bootstrap without user confirmation.
- No changes to existing `cluster admin deploy` semantics.
- No implicit destructive actions (destroy/stop) as part of this flow.

## UX Behavior

1. User runs `navigator sandbox create` (local or with `--remote`).
2. CLI attempts gRPC connection to the target cluster endpoint.
3. If connection succeeds, current behavior is unchanged.
4. If connection fails due to cluster unavailability:
   - Prompt: `No cluster is reachable. Bootstrap one now? [y/N]`
   - If user declines, exit with a clear error.
   - If user confirms, run bootstrap flow.
5. After bootstrap success, retry sandbox creation automatically.
6. For non-interactive stdin, do not prompt; fail with a message explaining confirmation is required.

## CLI/API Changes

### `crates/navigator-cli/src/main.rs`

- Extend `SandboxCommands::Create` with:
  - `--remote <ssh-host>` (optional)
  - `--ssh-key <path>` (optional, for parity with cluster admin remote deploy)
- Pass these options into `run::sandbox_create(...)`.

### `crates/navigator-cli/src/run.rs`

- Update `sandbox_create(...)` signature to accept remote bootstrap options.
- Add helper flow:
  - `resolve_bootstrap_target(remote, ssh_key) -> DeployOptions`
  - `confirm_bootstrap_if_interactive(...) -> Result<bool>`
  - `should_attempt_bootstrap(error) -> bool`
- On initial `grpc_client(server, tls)` failure:
  - If `should_attempt_bootstrap` is true, run confirmation + bootstrap.
  - Reconnect and proceed with existing create/watch/connect flow.
- Reuse existing bootstrap integration (`navigator_bootstrap::deploy_cluster` + `RemoteOptions`).

## Endpoint Resolution

- Local:
  - Bootstrap local cluster and connect using local gateway endpoint (current default path).
- Remote:
  - Bootstrap with `RemoteOptions::new(remote)` (+ optional `with_ssh_key`).
  - Derive cluster server endpoint from deployed handle (`handle.gateway_endpoint()`), then use that endpoint for gRPC calls in this invocation.
- Keep cluster-name defaults aligned with existing bootstrap behavior (`navigator` unless explicitly changed elsewhere).

## Confirmation Design

- Prompt only when stdin is a terminal.
- Default is **No** (safe by default).
- Accept `y`/`yes` (case-insensitive) as confirmation.
- Any other input, including empty input, aborts bootstrap.
- Non-interactive mode returns a clear actionable error:
  - e.g. "Cluster not reachable and bootstrap requires confirmation from an interactive terminal."

## Error Handling

- Only trigger bootstrap fallback on connection-level unreachability (endpoint unavailable/refused/timeout).
- Do not trigger bootstrap for:
  - TLS material/certificate errors
  - authorization/authentication failures
  - other non-connectivity request errors
- If bootstrap fails, return that failure directly with context.
- If bootstrap succeeds but reconnect fails, return reconnect error with endpoint info.

## Testing Plan

### Unit tests (new test module in `run.rs` or extracted helper module)

- Confirmation parser:
  - `y`, `Y`, `yes`, `YES` => confirm true
  - empty/other values => false
- Bootstrap decision helper:
  - connectivity errors => true
  - TLS/config/auth errors => false
- Endpoint selection helper:
  - local => local endpoint
  - remote => `http://<remote-host>:8080` via deployed handle metadata

### Integration-level tests (`crates/navigator-cli/tests/...`)

- Add focused tests for pure helper behavior where possible.
- Avoid full Docker/bootstrap in routine tests unless gated/explicitly opt-in.

## Documentation Updates

- Update command help text for `sandbox create` to include `--remote` and `--ssh-key`.
- Update `CONTRIBUTING.md` with examples:
  - `navigator sandbox create --remote user@host -- claude`
  - behavior when cluster is absent and confirmation is requested.

## Rollout Steps

1. Add CLI flags and plumb arguments.
2. Implement confirmation + fallback bootstrap helpers.
3. Integrate fallback into `sandbox_create` connection phase.
4. Add tests for helper logic and error classification.
5. Update docs/examples.
6. Validate manually:
   - local no-cluster path
   - remote no-cluster path
   - interactive decline/accept behavior
   - non-interactive behavior.

## Open Question

- Should we also add a future `--yes` flag for CI/non-interactive auto-confirmation?
  - Current plan: **No**, to satisfy explicit confirmation requirement and keep behavior safe.
