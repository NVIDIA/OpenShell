# openshell-sdk

`openshell-sdk` is the shared async Rust client for OpenShell gateways. It owns
the gRPC transport and auth stack so the CLI, the TUI, and language bindings
share one implementation of channel setup, TLS, OIDC refresh, and the
Cloudflare Access tunnel.

Designed in [RFC 0005](../../rfc/0005-shared-sdk-core-and-ts-binding/README.md).

## Two layers

- `OpenShellClient` — the curated, sandbox-focused surface: health, sandbox
  CRUD, readiness/deletion waits, and non-streaming exec.
- `raw` — direct access to the generated tonic clients for RPCs the curated
  surface doesn't yet cover (inference, providers, policy, logs, settings, SSH,
  forwarding).

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

Mirrors the modes the CLI exercises in production, so callers can move to the
SDK without losing connectivity options:

- Plaintext (local development)
- mTLS (self-deployed gateways with client certs)
- OIDC bearer over HTTPS (gateways behind an OAuth2/OIDC IdP)
- Cloudflare Access tunnel (hosted gateways)
- Insecure TLS (development/debug; certificate verification disabled)

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
