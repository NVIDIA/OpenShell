# openshell-sdk

`openshell-sdk` is the shared async Rust client for OpenShell gateways. It owns
the gRPC transport and auth stack so the CLI, the TUI, and language bindings
share one implementation of channel setup, TLS, OIDC refresh, and the
Cloudflare Access tunnel.

Designed in [RFC 0008](../../rfc/0008-shared-sdk-core-and-ts-binding/README.md).

## Two layers

- `OpenShellClient` — the curated, sandbox-focused surface: health, sandbox
  CRUD, readiness/deletion waits, and non-streaming exec.
- `raw` — direct access to the generated tonic clients for RPCs the curated
  surface doesn't yet cover (inference, providers, policy, logs, settings, SSH,
  forwarding).

The curated surface drives OIDC refresh automatically (proactively before a
request and reactively on `Unauthenticated`). The plain `raw_grpc`/
`raw_inference` accessors do not: they return a client bound to the current
token. When a refresher is wired, use `raw_grpc_fresh`/`raw_inference_fresh`
for a proactive refresh before the call, and `force_refresh` to recover after
a raw RPC returns `Unauthenticated`.

## Responsibilities

- Construct the gRPC channel and select the transport (plaintext vs TLS).
- Load TLS material and set up mTLS channels.
- Attach edge-auth bearer tokens and refresh OIDC tokens, with single-flight
  coalescing so only one refresh is in flight at a time.
- Proxy connections through the Cloudflare Access tunnel for hosted gateways.
- Map transport and gateway failures to a typed `SdkError` with a discriminable
  kind.

## Non-responsibilities

- Gateway-name resolution, default config-path lookups, and the OIDC browser
  flow. These are user-facing concerns owned by `openshell-cli`; the SDK
  consumes a `Refresh` trait the CLI implements.
- Reading tokens from disk. Callers pass an explicit token; the SDK performs no
  filesystem access.
- Defining the gRPC contract. The protos and generated types are owned by
  `openshell-core`.

## Transport and auth modes

Covers the connectivity modes the CLI exercises in production, except mTLS:

- Plaintext (local development)
- Server-authenticated TLS over HTTPS (system roots, or a pinned private CA via `ca_cert`)
- OIDC bearer over HTTPS (gateways behind an OAuth2/OIDC IdP)
- Cloudflare Access tunnel (hosted gateways)
- Insecure TLS (development/debug; certificate verification disabled)

mTLS (client certificates) is intentionally out of scope; gateways that require
it continue to use `openshell-cli`'s legacy mTLS path until that auth method is
retired.

## Public surface

`OpenShellClient::connect(ClientConfig)` returns a connected client exposing
`health`, `create_sandbox`, `get_sandbox`, `list_sandboxes`, `delete_sandbox`,
`wait_ready`, `wait_deleted`, and `exec`. Curated types (`SandboxSpec`,
`SandboxRef`, `Health`, `ListOptions`, `ExecOptions`, `SandboxPhase`) use
SDK-shaped enums rather than raw proto integers.

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

## Consumers

`openshell-cli`, `openshell-tui`, and `openshell-sdk-node` (published as
`@openshell/sdk`).

## Notes

- Async-only. Tonic is async-native; callers needing a blocking call can wrap
  with their own runtime.
- The surface is alpha and will grow as more RPCs graduate from `raw` into the
  curated client.
