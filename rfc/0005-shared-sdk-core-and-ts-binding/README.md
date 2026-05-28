---
authors:
  - "@mdubrinsky"
state: review
links:
  - https://linear.app/nvidia/issue/OSGH-110/python-and-typescript-sdk-support
---

# RFC 0005 - Shared Rust SDK core and TypeScript binding

## Summary

Extract a new `openshell-sdk` Rust crate from gRPC client plumbing that today lives in `openshell-cli`, and ship a TypeScript SDK (`@openshell/sdk`) as a [napi-rs](https://napi.rs) wrapper over that crate. Refactor `openshell-cli` to consume `openshell-sdk` so the CLI and the TS SDK share a single transport, auth, and error implementation. The pure-Python SDK at `python/openshell/` stays as-is for this RFC; migrating it onto the shared core is deferred to a follow-up.

## Motivation

OpenShell currently has one programmable surface (Python) and a CLI. The Python SDK is a hand-written gRPC client in `python/openshell/sandbox.py` that duplicates concerns already implemented in Rust (`openshell-cli/src/tls.rs` and `openshell-cli/src/oidc_auth.rs`):

- TLS material loading, mTLS channel setup
- Edge-auth bearer token attachment
- OIDC token refresh
- Plaintext vs TLS transport selection

Adding a TypeScript SDK by hand-writing a third gRPC client would extend the duplication. Three reasons to share a Rust core instead:

1. **Multi-language support without re-implementing the transport per language.** We expect TS/Node users (TS-authored agents, web tooling). A shared transport layer keeps retry, auth refresh, and streaming consistent across bindings.
2. **The Rust transport already runs in production.** The CLI exercises every auth mode today.
3. **Establishes the pattern for other-language bindings.** If this works for TS, the same crate can later back a PyO3 binding and replace the pure-Python SDK.

## What exists today

- **Python SDK.** `python/openshell/sandbox.py`, hand-written gRPC against the existing protos.
- **CLI transport stack.** Full set of transport/auth modes implemented in `openshell-cli/src/tls.rs`, `openshell-cli/src/oidc_auth.rs`, and `openshell-cli/src/edge_tunnel.rs`. Runs in production today.

## Non-goals

- **Replacing the pure-Python SDK.** That migration is a separate, larger decision (API parity, deprecation window, packaging). This RFC keeps Python on its current pure-Python stack and only ensures the shared core is shaped so a future PyO3 wrapper is feasible.
- **gRPC contract changes.** The SDK is a client of the existing `proto/openshell.proto`, `proto/sandbox.proto`, `proto/inference.proto`. No service or message changes.
- **Browser / WebAssembly support.** napi-rs targets Node only. A browser SDK is a separate future RFC.
- **Bundling the `openshell` CLI binary inside the npm package.** Unlike the Python wheel (which uses maturin's `bindings = "bin"` to bundle the CLI), the TS SDK is gRPC-only. CLI installation stays a separate concern.
- **Streaming `exec` in the initial slice.** Tracked separately.

## Proposal

### New and changed crates

```
crates/
  openshell-sdk/          NEW. Pure Rust async client library. No FFI, no CLI deps.
  openshell-sdk-node/     NEW. napi-rs wrapper over openshell-sdk. Ships as @openshell/sdk.
  openshell-cli/          REFACTORED. Channel/auth code moves out; CLI consumes openshell-sdk.
  openshell-core/         UNCHANGED. Still owns proto codegen; openshell-sdk depends on it.
```

### `openshell-sdk` surface

```rust
pub struct ClientConfig {
    pub gateway: String,                 // "https://..." or "http://..."
    pub tls: Option<TlsMaterials>,       // required for mTLS, ignored for plaintext
    pub auth: Option<AuthConfig>,        // bearer token or OIDC refresh closure
    pub timeout: Option<Duration>,       // default: None (no client-side timeout)
}

pub enum AuthConfig {
    Bearer(String),
    Oidc { token: String, refresh: Arc<dyn Refresh> },
}

pub struct OpenShellClient { /* tonic Channel + interceptor */ }

impl OpenShellClient {
    pub async fn connect(config: ClientConfig) -> Result<Self, SdkError>;

    pub async fn health(&self) -> Result<Health, SdkError>;
    pub async fn create_sandbox(&self, spec: SandboxSpec) -> Result<SandboxRef, SdkError>;
    pub async fn get_sandbox(&self, name: &str) -> Result<SandboxRef, SdkError>;
    pub async fn list_sandboxes(&self, opts: ListOptions) -> Result<Vec<SandboxRef>, SdkError>;
    pub async fn delete_sandbox(&self, name: &str) -> Result<bool, SdkError>;
    pub async fn wait_ready(&self, name: &str, timeout: Duration) -> Result<SandboxRef, SdkError>;
    pub async fn wait_deleted(&self, name: &str, timeout: Duration) -> Result<(), SdkError>;
    pub async fn exec(&self, name: &str, cmd: &[String], opts: ExecOptions) -> Result<ExecResult, SdkError>;
}
```

### `openshell-sdk-node` surface

A thin napi-rs wrapper exposing the same surface as JS classes / objects. Idiomatic camelCase (`createSandbox`, `waitReady`) is generated automatically from snake_case Rust by napi-derive.

### CLI refactor

Transport mechanics move out of `openshell-cli` and into `openshell-sdk`: gRPC channel construction, TLS material handling, request interceptors, and the Cloudflare Access tunnel. The CLI keeps everything user-facing — gateway-name resolution, default-path lookups, and the OIDC browser flow. The SDK never sees a browser; it consumes a `Refresh` trait that the CLI implements.

### Transport and auth modes

MVP must support the same five transport/auth modes the CLI exercises today, so a CLI user can move to the SDK without losing connectivity options:

- Plaintext (local development)
- mTLS (self-deployed gateways with client certs)
- OIDC bearer over HTTPS (gateways behind an OAuth2/OIDC IdP)
- Cloudflare Access tunnel (hosted gateways)
- Insecure TLS (development/debug; certificate verification disabled)

### Current leanings

| Decision                                    | Choice                                                                                                                                                                                                                                                                                                 | Rationale                                                                                                                                                                                                                                                                |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Binding tool for TS**                     | napi-rs v3                                                                                                                                                                                                                                                                                             | Required for `ThreadsafeFunction<T, Promise<R>>` + `call_async`. Considered: UniFFI (no stable TS target), Diplomat (smaller community, JS support nascent), wit-bindgen (Node packaging not yet ergonomic).                                                       |
| **Tokio runtime ownership at FFI boundary** | napi's ambient tokio runtime is available only inside `async fn` entry points. Every user-facing napi function that needs the runtime must be `async`. No `Handle` plumbing in `ClientConfig`.                                                                                                         | Sync `#[napi] fn` runs on the JS thread with no reactor; `tokio::spawn` from sync napi context panics with "no reactor running".                                                                                                                                         |
| **API shape**                               | Async-only, no blocking facade                                                                                                                                                                                                                                                                         | Tonic is async-native; a blocking facade would require `block_on` plumbing and confuse the JS Promise contract. Callers needing sync can wrap with `tokio::runtime::Runtime::block_on` themselves.                                                                          |
| **Error type**                              | `thiserror` enum in `openshell-sdk`, mapped to napi `Error` with a `code` field for TS discriminated-union ergonomics                                                                                                                                                                                  | Better than the Python SDK's single `SandboxError(RuntimeError)`. Lets TS consumers `switch` on error kind.                                                                                                                                                              |
| **Retry policy**                            | Per-call configurable; default = no retry                                                                                                                                                                                                                                                              | Matches the Python SDK. Advanced users opt in.                                                                                                                                                                                                                           |
| **OIDC refresh trait**                      | SDK accepts a `Refresh` trait with a domain error type, not `napi::Error`. CLI provides the browser-flow impl. Node binding wraps a JS callback as a `ThreadsafeFunction<(), Promise<String>>`.                                                                                       | Keeps `openshell-sdk` napi-free.                                                                                                                                                                                                                                         |
| **Single-flight refresh coalescing**        | Lives in `openshell-sdk` core, not in the binding.                                                                                                                                                                                                                                                     | napi does not provide it; standard OIDC pattern needs it (one refresh in flight, all waiters share the result).                                                                                                                                                          |
| **OIDC refresh cancellation**               | Rust-side future drop does not propagate to JS. In-flight JS refresher promise runs to completion; SDK ignores late-arriving values.                                                                                                                                                                   | Trait does not need cooperative cancellation.                                                                                                                                                                                                                            |
| **Streaming pattern**                       | Iterator-style: a napi class with an async `next()` method, drop-based cancellation, and a thin TS shim layering `for await` on top. Not native AsyncGenerator.                                                                                                                                        | napi-rs v3.8 has no native AsyncGenerator return type.                                                                                                                                                                                              |
| **Auth token file loading**                 | NOT in `openshell-sdk` directly. Callers pass an explicit token. A separate convenience helper in `openshell-cli` (or a thin helper crate) handles the `~/.config/openshell/gateways/<name>/edge_token` lookup.                                                                                        | Keeps `openshell-sdk` free of filesystem access. Usable as a library without CLI assumptions.                                                                                                                                                                            |
| **SDK layering scope (MVP)**                | Sandbox-focused. High-level methods cover health, sandbox CRUD, waits, and non-streaming exec. A `raw` module re-exports generated tonic clients as an escape hatch. Inference, providers, policy, logs, settings, SSH, forwarding, and completions are out of MVP and deferred.                       | The `raw` escape hatch lets callers reach RPCs the high-level surface doesn't yet cover.                                                                                                                                                                                 |
| **TypeScript API model**                    | Curated SDK types, not raw proto shapes. Enum-valued fields use string literals (e.g., `"Pending"`), not numeric proto enums. Captured high-level types: `SandboxSpec`, `SandboxRef`, `Health`, `ListOptions`, `ExecOptions`.                                                                          | TS DX is better with discriminated string unions than with numeric proto enums.                                                                                                                                                                                          |

## Implementation plan

Phases ordered by dependency. No time estimates. This RFC establishes direction; detailed contracts (the `Refresh` trait shape, error codes, exec semantics) settle at implementation time.

### Phase 1 — Refactor and extract `openshell-sdk`

- Create `crates/openshell-sdk/` with transport, auth, error, and edge-tunnel modules.
- Execute the CLI refactor described above.
- Exit criteria: all existing `mise run test` and `mise run e2e` paths pass. No new SDK consumers yet.

### Phase 2 — High-level SDK methods

- Implement `health`, `create_sandbox`, `get_sandbox`, `list_sandboxes`, `delete_sandbox`, `wait_ready`, `wait_deleted`, non-streaming `exec`.
- Unit tests with a mock tonic server.
- Settle the `Refresh` trait contract: single-flight semantics, proactive vs reactive trigger, deadline, retry-after-refresh-failure, terminal-failure signalling.

### Phase 3 — `openshell-sdk-node` napi binding

- Build the JS-facing client surface over `openshell-sdk`.
- Wire the OIDC refresh callback path between Rust and JS.
- Map SDK errors to JS errors with a discriminable `code` field.
- Resolve the tunnel-vs-refresh interaction with one targeted test (does the CF tunnel re-handshake on bearer rotation, swap headers in place, or tear down and rebuild?).
- Smoke test against a plaintext local gateway.

## Migration and compatibility

- **CLI surface preserved.** The phase 1 refactor does not change `openshell-cli` flags, behavior, or output. Existing scripts continue to work.
- **gRPC contract unchanged** (see Non-goals).
- **Python SDK frozen.** The pure-Python SDK is unaffected by this RFC.
- **Alpha contract.** `@openshell/sdk` ships under `0.0.0-alpha.x` until the surface stabilizes; no semver guarantee before 1.0.

## Risks

- **CLI regression during phase 1.** Mitigation: extraction PR ships first with no SDK consumers, with the existing CLI tests as the regression surface.
- **napi-rs prebuilt binary CI complexity.** Six-target build matrices break in interesting ways (musl static linking, macOS codesigning, cross-compilation for aarch64). The v3 toolchain has only been exercised on darwin-arm64 so far; the full cross-platform matrix is unproven. Mitigation: lean on napi-rs's published workflow template; treat the first publish as the trigger for completing the build matrix.
- **Python/TS SDK behavior drift.** While Python stays pure-Python over gRPC, behavior (timeouts, retry, error mapping) may drift from the Rust SDK. Mitigation: keep the Python SDK frozen during this RFC's implementation; track parity as a precondition for a future Python-on-shared-core RFC.
- **Refresh contract details.** The FFI mechanism is settled. Still unspecified: proactive vs reactive trigger, deadline, retry-after-refresh-failure, terminal-failure signalling. Mitigation: design alongside phase 2.
- **Tunnel-vs-refresh interaction.** The CF tunnel captures bearer headers at connection time; bearer rotation mid-session is not yet specified. Mitigation: settle in phase 3 with one targeted test before npm alpha publish.

## Alternatives

- **Pure-TS gRPC client (e.g., `@connectrpc/connect`, `ts-proto`).** Cheaper and faster initially, no shared runtime. Loses all the shared-core benefits (auth refresh, retry, error taxonomy) and locks us into duplicating logic per language. Reasonable if the project decided the shared-core direction is overkill; this RFC argues it's not.
- **TS calls Python via subprocess or IPC.** Rejected — terrible DX, forces a Python runtime on Node consumers.
- **UniFFI for both Python and TS.** UniFFI's TS target is not yet stable. Re-evaluate once it lands.
- **Diplomat (Rust → JS/Dart/Kotlin).** Smaller community, JS support less proven.
- **`wit-bindgen` + WebAssembly component model.** The likely long-term target once Node packaging of wasm components matures.
- **Do nothing; tell TS users to use the gRPC stubs directly.** Possible, but leaves every TS consumer to roll their own wrapper.

## Prior art

- **Polars** — Rust core, PyO3 for Python, napi-rs for Node. Same pattern.
- **swc** and **Turbopack** — large napi-rs projects in the JS tooling ecosystem, demonstrate the publishing/CI patterns.
- **Bitwarden SDK** — Rust core with UniFFI bindings; useful reference for Refresh-trait-style auth design even though we're not using UniFFI.
- **1Password Connect SDK** — multi-language SDK over a shared gRPC contract, same design choice in a different domain.

## Open questions

- **Retry policy shape.** Builder on `ClientConfig` (declarative) or `tower::Layer` (composable)? Composable is more flexible; declarative is friendlier for napi/PyO3 consumers who can't construct a `Layer`.
- **Should `OpenShellClient::from_gateway_name(name)` exist in `openshell-sdk` at all,** or only in a CLI-config helper crate? Tradeoff between ergonomics and keeping `openshell-sdk` filesystem-free.
