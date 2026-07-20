# openshell-sdk

`openshell-sdk` is the shared async Rust client for OpenShell gateways. It owns
gRPC channel setup, TLS, OIDC refresh, and the Cloudflare Access tunnel so the
CLI, the TUI, and language bindings share one client implementation. Callers
pass an explicit bearer token; the SDK does no filesystem access and no
gateway-name resolution.

## Two layers

- `OpenShellClient` — the curated, sandbox-focused surface: health, sandbox
  CRUD, readiness/deletion waits, and non-streaming exec.
- `raw` — direct access to the generated tonic clients for RPCs the curated
  surface doesn't yet cover (inference, providers, policy, logs, settings, SSH,
  forwarding).

## Auth and refresh

The curated surface drives OIDC refresh automatically: proactively before a
request and reactively on `Unauthenticated`. Refreshes are single-flight, so
only one is in flight at a time.

The plain `raw_grpc`/`raw_inference` accessors do not refresh; they return a
client bound to the current token. When a refresher is wired, use
`raw_grpc_fresh`/`raw_inference_fresh` to refresh before the call, and
`force_refresh` to recover after a raw RPC returns `Unauthenticated`.

The SDK consumes a `Refresh` trait that the caller implements; it does not run
the OIDC browser flow itself.

## Transport modes

- Plaintext (local development)
- Server-authenticated TLS (system roots, or a pinned private CA via `ca_cert`)
- OIDC bearer over HTTPS (gateways behind an OAuth2/OIDC IdP)
- Cloudflare Access tunnel (hosted gateways)
- Insecure TLS (development/debug; certificate verification disabled)

mTLS (client certificates) is not supported.

## Public surface

`OpenShellClient::connect(ClientConfig)` returns a connected client exposing
`health`, `create_sandbox`, `get_sandbox`, `list_sandboxes`, `delete_sandbox`,
`wait_ready`, `wait_deleted`, and `exec`. Curated types (`SandboxSpec`,
`SandboxRef`, `Health`, `ListOptions`, `ExecOptions`, `SandboxPhase`) use
SDK-shaped enums rather than raw proto integers. Failures map to a typed
`SdkError` with a discriminable kind.

## Modules

| Module | Purpose |
|---|---|
| `client` | High-level `OpenShellClient` and the curated sandbox surface. |
| `config` | `ClientConfig`, `AuthConfig`. |
| `transport` | Channel construction, TLS resolution, request interceptors. |
| `auth` | `EdgeAuthInterceptor` for bearer-token attachment. |
| `oidc` | OIDC token handling at the transport layer. |
| `refresh` | `Refresh` trait and single-flight refresh coalescing. |
| `edge_tunnel` | Cloudflare Access tunnel dialer. |
| `error` | `SdkError` taxonomy. |
| `types` | Curated request/response types and proto conversions. |
| `raw` | Escape hatch re-exporting the generated tonic clients. |

## Notes

- Async-only. Tonic is async-native; callers needing a blocking call can wrap
  with their own runtime.
- The curated surface will grow as more RPCs graduate from `raw`.
