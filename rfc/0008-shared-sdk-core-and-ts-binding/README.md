---
authors:
  - "@mdubrinsky"
state: review
links:
  - https://linear.app/nvidia/issue/OSGH-110/python-and-typescript-sdk-support
  - https://github.com/NVIDIA/OpenShell/pull/2122
  - https://github.com/NVIDIA/OpenShell/pull/1862
---

# RFC 0008 - SDK architecture: shared core, per-language bindings

## Summary

The goal for every OpenShell SDK is one thing: a client that is idiomatic and performant in its own language. How that is achieved is immaterial. Two things are shared across all of them: the `proto/` wire contract, and single-flight OIDC refresh, the one behavior that must be byte-identical. Everything a user touches, the types, errors, resource management, and async model, is built to feel native to the language.

A language reaches that goal one of two ways. A native binding generates its client from `proto/` and implements the surface in the language (TypeScript over connect-es, Go over grpc-go). An FFI binding hand-writes the surface over the shared `openshell-sdk` Rust core, which supplies transport, auth, and refresh (Python over PyO3). Both are first-class.

Extract the `openshell-sdk` Rust crate as the shared transport, auth, and error core. It backs the Rust consumers, `openshell-cli` and `openshell-tui`, directly, and is the substrate FFI bindings wrap.

## Principles

This document is the grounding for OpenShell's SDKs. A future language SDK decides its binding strategy and shapes its surface against these principles and the contract below.

- **Idiomatic first.** An SDK feels native to its language: the ecosystem's types, error handling, async model, and resource management. A user should not be able to tell whether the client is native or FFI-backed.
- **Performant.** It uses the ecosystem's best transport and adds no overhead a hand-written client would not.
- **Share only what must be shared.** The `proto/` contract and single-flight OIDC refresh are shared across every SDK. Everything else is per-language.
- **Mechanism is a means, not a mandate.** Native codegen and FFI over `openshell-sdk` are equal options, chosen per language by the criteria in [Choosing a binding strategy](#choosing-a-binding-strategy).

## Motivation

OpenShell has one programmable surface today (Python) plus a CLI. The Python SDK is a hand-written gRPC client in `python/openshell/sandbox.py` that reimplements plumbing already written in Rust (`openshell-cli/src/tls.rs`, `oidc_auth.rs`, `edge_tunnel.rs`):

- TLS material loading, mTLS channel setup
- Edge-auth bearer token attachment
- OIDC token refresh
- Plaintext vs TLS transport selection

Every new SDK written entirely by hand repeats that plumbing. Two properties of OpenShell let us stop repeating it:

1. **The wire contract is already shared through `proto/`.** RPCs, messages, and types change often and regenerate cheaply into any language, so a generated client inherits the contract for free.
2. **Only one behavior is genuinely stateful across languages.** Single-flight OIDC refresh (one refresh in flight, all waiters share the result, proactive before a call and reactive on `Unauthenticated`) is the piece worth pinning identical.

So the plumbing is shared through one Rust implementation, and each language spends its effort only on an idiomatic surface. The `openshell-sdk` crate is that shared implementation: it backs the CLI and TUI directly, dedupes the production transport stack between them, and is the reference every other binding matches or wraps.

## What exists today

- **Python SDK.** `python/openshell/sandbox.py`, hand-written gRPC against the existing protos. Synchronous, with frozen dataclasses, context managers, and a `cloudpickle`-based `exec_python`.
- **CLI transport stack.** The full set of transport and auth modes, in `openshell-cli/src/tls.rs`, `oidc_auth.rs`, and `edge_tunnel.rs`. Runs in production.
- **TypeScript SDK prototype.** `sdk/typescript/` (PR #2122), a native client generated from `proto/` over connect-es. Covers health, sandbox CRUD, waits, and streamed exec. The reference for the native-binding pattern.

## Non-goals

- **Executing the Python migration.** This RFC names PyO3 over `openshell-sdk` as Python's binding strategy, but the migration itself (API parity, deprecation window, packaging) is a separate decision. The existing pure-Python client stays until then.
- **gRPC contract changes.** The SDKs are clients of the existing `proto/openshell.proto`, `proto/sandbox.proto`, `proto/inference.proto`. Expanding the RPC surface to move capability server-side (so thin SDKs gain reach without per-language code) is a related but separate track; see RFC 0007.
- **Browser / WebAssembly support.** A browser SDK is a separate future RFC.
- **Bundling the `openshell` CLI binary inside a language package.** The SDKs are gRPC clients. CLI installation stays a separate concern.

## Proposal

### The SDK contract

Every SDK, native or FFI, delivers the same contract:

- **An idiomatic, hand-written surface.** The language's own types, error handling, resource management, and async model. Never an auto-generated 1:1 mirror of the Rust API.
- **The five transport and auth modes** (see [Transport and auth modes](#transport-and-auth-modes)).
- **Single-flight OIDC refresh** with the shared observable behavior.
- **Curated types with string-valued enums**, plus a `raw` escape hatch exposing the generated stubs for RPCs the curated surface does not cover.
- **A stable string-coded error taxonomy** (`not_found`, `already_exists`, `auth`, `invalid_config`, `rpc`, ...) mapped from gRPC status codes.

The strategies differ only in where the core plumbing (transport, auth, refresh) comes from:

- A **native binding** generates stubs from `proto/` (connect-es for TS; `protoc-gen-go` + `grpc-go`, or connect-go, for Go) and reimplements the plumbing in the language. Its refresh is pinned to the conformance suite.
- An **FFI binding** inherits the plumbing from `openshell-sdk` and hand-writes only the surface on top. Its refresh is the shared core implementation, so it needs no conformance pin.

FFI is not a shortcut around surface design: it removes the need to rebuild the core plumbing, not the need to write a good surface.

### Choosing a binding strategy

Both strategies satisfy the contract. Pick the better fit for the language, weighing:

- Is a pure-language gRPC stack mature and idiomatic in the ecosystem?
- Does the ecosystem already ship and expect compiled extensions?
- Would an FFI distribution model break a core ecosystem property (for example, Go's static, cross-compiled binaries)?
- Does sharing the plumbing meaningfully reduce risk (one audited OIDC and TLS path) versus a per-language reimplementation?

| Language | Strategy | Why it fits |
| --- | --- | --- |
| TypeScript | Native (connect-es) | A clean pure-JS client over generated stubs; shipping prebuilt binaries across Node targets would cost more and add nothing. |
| Go | Native (grpc-go) | grpc-go is idiomatic and fast; cgo would forfeit static, cross-compiled binaries, Go's core distribution property. |
| Python | FFI (PyO3) | The package already ships as a compiled wheel (maturin), so a compiled core costs nothing new, and one shared plumbing core removes a second transport/auth/refresh implementation. The idiomatic surface (frozen dataclasses, context managers, `exec_python`, sync and async) stays hand-written Python over the core. |

### Crate and package layout

```
crates/
  openshell-sdk/          NEW. Shared Rust async client core. Backs the CLI and TUI directly
                          and is the substrate FFI bindings wrap.
  openshell-cli/          REFACTORED. Channel/auth code moves out; CLI consumes openshell-sdk.
  openshell-tui/          REFACTORED. Consumes openshell-sdk.
  openshell-core/         UNCHANGED. Still owns proto codegen; openshell-sdk depends on it.

sdk/
  typescript/             Native binding: generated from proto/ (connect-es). @nvidia/openshell-sdk.
  go/                     Native binding, planned: generated from proto/ (protoc-gen-go + grpc-go).

python/openshell/         FFI binding: PyO3 over openshell-sdk (leading candidate; migration is
                          a separate decision, see Non-goals). Hand-written client until then.
```

### `openshell-sdk` (Rust) surface

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

An FFI binding wraps this surface and re-presents it in the host language. Because the core is async (tonic/tokio), a binding can expose an async surface mapped from these futures (for Python, via `pyo3-async-runtimes`) or a synchronous one over `block_on`, or both.

### CLI refactor

Transport mechanics move out of `openshell-cli` into `openshell-sdk`: gRPC channel construction, TLS material handling, request interceptors, and the Cloudflare Access tunnel. The CLI keeps everything user-facing: gateway-name resolution, default-path lookups, and the OIDC browser flow. The SDK never sees a browser; it consumes a `Refresh` trait that the CLI implements.

### Transport and auth modes

The MVP preserves the five transport and auth modes the CLI exercises today, so a CLI user can move to any SDK without losing connectivity options:

- Plaintext (local development)
- mTLS (self-deployed gateways with client certs)
- OIDC bearer over HTTPS (gateways behind an OAuth2/OIDC IdP)
- Cloudflare Access tunnel (hosted gateways)
- Insecure TLS (development/debug; certificate verification disabled)

A binding may realize a mode differently: an FFI binding inherits the modes from the core, and a native binding may run the Cloudflare Access tunnel as a loopback sidecar rather than in-language. The set of supported modes is the same.

### Design decisions

| Decision | Choice | Rationale |
| --- | --- | --- |
| **Binding strategy** | Per-language over one shared `proto/` contract: native codegen or FFI over `openshell-sdk`, chosen by ecosystem fit (native for TS/Go, FFI/PyO3 for Python). | Each ecosystem gets the mechanism that fits it best; the shared contract and core keep the bindings aligned regardless. |
| **Shared behavior** | Single-flight OIDC refresh lives in `openshell-sdk`. FFI bindings inherit it; native bindings match it against a conformance suite. | It is the only genuinely stateful cross-language behavior, so it is worth one shared implementation plus a pin on the reimplementations. |
| **Error model** | Stable string-coded taxonomy, mapped from gRPC status codes. Rust uses a `thiserror` enum; bindings mirror the codes. | Lets consumers discriminate on error kind (`switch`/`match`) instead of parsing messages. |
| **Type model** | Curated SDK types, not raw proto shapes. Enum fields use string literals, not numeric proto enums. Curated set: `SandboxSpec`, `SandboxRef`, `Health`, `ListOptions`, `ExecOptions`, `ExecResult`. | Reads naturally in each language and stays stable as the proto evolves. |
| **Escape hatch** | Each SDK exposes the generated stubs (`raw`) for RPCs the curated surface does not cover. | Callers reach any RPC without waiting for a curated wrapper. |
| **MVP scope** | Sandbox-focused: health, sandbox CRUD, waits, exec (streamed where the language allows). Inference, providers, policy, logs, settings, SSH, and forwarding are deferred. | Ship the common path first; grow the curated surface over time. |
| **Auth token file loading** | Not in `openshell-sdk`. Callers pass an explicit token; the CLI or a helper resolves `~/.config/openshell/gateways/<name>/...`. | Keeps the core free of filesystem access; usable as a plain library. |
| **Retry policy** | Per-call configurable; default off. | Predictable behavior by default; callers opt into retries explicitly. |
| **Cloudflare Access tunnel** | Native bindings may run it out-of-process as a language-agnostic loopback sidecar rather than in-language. | Avoids reimplementing the WebSocket tunnel per language; the binding points at the local endpoint and the header mode covers the rest. |

## Implementation plan

Phases ordered by dependency. No time estimates. This RFC establishes direction; detailed contracts (the `Refresh` trait shape, error codes, exec semantics) settle at implementation time.

### Phase 1 - Extract `openshell-sdk` and refactor the Rust consumers

- Create `crates/openshell-sdk/` with transport, auth, error, and edge-tunnel modules.
- Refactor `openshell-cli` and `openshell-tui` onto it.
- Exit criteria: existing `mise run test` and `mise run e2e` paths pass. No behavior change.

### Phase 2 - High-level Rust SDK methods

- Implement `health`, `create_sandbox`, `get_sandbox`, `list_sandboxes`, `delete_sandbox`, `wait_ready`, `wait_deleted`, and non-streaming `exec`.
- Unit tests against a mock tonic server.
- Settle the `Refresh` trait contract: single-flight semantics, proactive vs reactive trigger, deadline, retry-after-refresh-failure, terminal-failure signalling.

### Phase 3 - Language bindings

- TypeScript (`sdk/typescript/`, PR #2122) is the reference native binding: generated from `proto/`, curated surface, error taxonomy, transport modes.
- Go (`sdk/go/`) follows over `protoc-gen-go` + `grpc-go` (or connect-go for symmetry with TS).
- Python moves to a PyO3 binding over `openshell-sdk`, keeping its idiomatic Python surface and retiring the hand-written plumbing (the migration is scoped separately; see Non-goals).
- Stand up the shared OIDC-refresh conformance suite for the native bindings (TS, Go).

## Migration and compatibility

- **CLI and TUI surface preserved.** The phase 1 refactor does not change flags, behavior, or output. Existing scripts continue to work.
- **gRPC contract unchanged** (see Non-goals).
- **Python client stays until migrated.** The hand-written pure-Python client keeps working until the PyO3 migration is decided and executed.
- **Independent package versioning.** Each SDK package versions on its own release cadence and carries a `0.0.0` placeholder stamped from the release tag at publish time. Surfaces stay pre-1.0 (no semver guarantee) until stabilized.

## Risks

- **CLI/TUI regression during phase 1.** Mitigation: the extraction lands first with no new consumers, using the existing CLI and TUI tests as the regression surface.
- **Native binding drift.** A native binding reimplements the thin surface, so timeouts, retry, error mapping, and refresh can diverge from the core (FFI bindings cannot, since they inherit it). Mitigation: the OIDC-refresh conformance suite pins the stateful part; curated types and the shared error taxonomy keep the surfaces aligned; treat drift as a bug against the suite.
- **Proto surface growth.** Expanding what SDKs can do by pushing capability into RPCs (for example, file transfer, per RFC 0007) grows the gateway API and its authz surface. Track that as its own decision, not a side effect of this RFC.
- **Cloudflare Access tunnel per language.** The loopback-sidecar approach is proven for the CLI's inline tunnel but not yet for every native binding. Mitigation: settle the sidecar contract before the first tunnel-backed native release.

## Alternatives

- **One binding mechanism for every language.** Either FFI everywhere (bind one Rust core from Node, Python, and Go alike) or native everywhere. FFI everywhere forfeits Go's static, cross-compiled binaries and saddles Node with a multi-target prebuilt matrix for a thin, fast-changing surface. Native everywhere makes Python reimplement transport, auth, and refresh it could otherwise inherit through a binding, and drop the compiled-wheel machinery it already runs. The per-language strategy takes the better fit for each instead.
- **UniFFI / Diplomat / wit-bindgen for the FFI bindings** instead of hand-written PyO3. Multi-language binding generators; PyO3 is the standard, well-supported path for Python and is enough for a single FFI target today. `wit-bindgen` plus the WebAssembly component model is a plausible long-term browser story, not a fit here.
- **TS or Go calls Python via subprocess or IPC.** Rejected. Terrible DX and forces a Python runtime on other-language consumers.
- **Do nothing; tell users to use the generated gRPC stubs directly.** Rejected. Leaves every consumer to roll their own transport, auth, refresh, and error handling.

## Prior art

- **1Password Connect SDK** and **gRPC's own multi-language codegen.** Multiple languages over a shared wire contract, each generated natively. The model for the native bindings.
- **Polars** (Rust core, PyO3 for Python, napi for Node) and compiled-extension packages like **pydantic-core** and **cryptography**. The model for the Python FFI binding: a compiled core with a hand-written idiomatic surface is normal and well-tooled in the Python ecosystem.

## Open questions

- **Retry policy shape.** Builder on `ClientConfig` (declarative) or `tower::Layer` (composable) in the Rust crate? Composable is more flexible; declarative is friendlier for a native reimplementation.
- **`from_gateway_name`.** Should it exist in `openshell-sdk`, or only in a CLI/config helper? Tradeoff between ergonomics and keeping the core filesystem-free.
- **Server-side vs client-side capability.** As the curated surface grows, some capability (file transfer, policy prove) is cheaper to add once as an RPC than to reimplement per language, at the cost of gateway surface and authz. Coordinate scope with RFC 0007.
- **Python migration timing and fallback.** When to execute the PyO3 migration, and whether to keep a pure-Python path for environments that cannot install a compiled extension.
