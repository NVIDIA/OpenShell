<!--
SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Supervisor Middleware Content Guard

> [!WARNING]
> Supervisor middleware is a research preview. Its policy and service contracts may change without compatibility guarantees. Use it only to prototype and evaluate middleware integrations.

This configured-literal guard applies the same case-sensitive terms to UTF-8 HTTP request bodies, complete HTTP response bodies, and client WebSocket text messages. It is not a general PII detector.

The service implements both HTTP middleware protocols, so one build works with every OpenShell version. It is the reference for migrating a middleware service to HTTP protocol 2; see [Serve both HTTP protocols](#serve-both-http-protocols).

> [!WARNING]
> This intentionally simple implementation demonstrates the supervisor middleware service contract. It is not a complete or reliable content guard and must not be used as a security control. It handles only UTF-8 HTTP request and response bodies and WebSocket text messages with case-sensitive literal terms, merges overlapping literal match ranges before redaction, and does not address encodings, transformations, normalization, binary WebSocket messages, upstream-to-client messages, or adversarial inputs that a production content guard must handle.

## Serve both HTTP protocols

OpenShell has two HTTP middleware protocols:

- HTTP protocol 1, the legacy protocol from 0.1, evaluates requests with `SupervisorMiddleware.EvaluateHttpRequest` and responses with `HttpResponsePreReturn.Evaluate`. OpenShell 0.2.0 removes it.
- HTTP protocol 2 evaluates both directions with `EvaluateHttp`, on `HttpRequestPreCredentials` and `HttpResponsePreReturn`. A gateway or supervisor that runs HTTP protocol 2 advertises the `openshell.supervisor-middleware.http-v2` capability when it calls `Describe`.

A service that serves both keeps working while gateways and supervisors of different versions run side by side. To migrate a service the way this example does:

1. Advertise `http-v2` as a supported capability, not a required one: pass `[SUPERVISOR_MIDDLEWARE_HTTP_V2.to_string()]` as the additional capabilities of `extension_metadata`. Peers without version 2, including OpenShell v0.1.2 and earlier, refuse a service that requires it.

2. Build the manifest for each `Describe` call. Return version 2 HTTP bindings when the caller advertises `http-v2`, which `peer_supports` from `openshell_core::extension_protocol` checks, and legacy HTTP bindings otherwise. The gateway and every sandbox supervisor call `Describe` separately and may run different OpenShell versions, so do not share one manifest between callers.

   ```rust
   async fn describe(
       &self,
       request: Request<MiddlewareDescribeRequest>,
   ) -> Result<Response<MiddlewareManifest>, Status> {
       let caller = request.into_inner().gateway;
       let http_v2 = caller
           .as_ref()
           .is_some_and(|caller| peer_supports(caller, SUPERVISOR_MIDDLEWARE_HTTP_V2));
       let manifest = manifest(http_v2);
       validate_gateway_metadata(
           ExtensionFamily::SupervisorMiddleware,
           MANIFEST_NAME,
           manifest.extension.as_ref(),
           caller,
       )
       .map_err(|error| Status::failed_precondition(error.to_string()))?;
       Ok(Response::new(manifest))
   }
   ```

   A version 2 binding sets `http_protocol_version: 2` and lists the body modes the service can select in `supported_http_body_modes`. A legacy binding leaves both fields unset, exactly as before. WebSocket bindings are the same in both manifests.

   ```rust
   let http_binding = |operation: SupervisorMiddlewareOperation, phase| {
       let binding = MiddlewareBinding {
           operation: operation as i32,
           phase: phase as i32,
           max_payload_bytes: MAX_PAYLOAD_BYTES,
           ..Default::default()
       };
       if http_v2 {
           MiddlewareBinding {
               http_protocol_version: 2,
               supported_http_body_modes: vec![HttpBodyMode::Buffered as i32],
               ..binding
           }
       } else {
           binding
       }
   };
   ```

3. Implement both RPC sets on one inspection core, and serve `SupervisorMiddleware`, `HttpRequestPreCredentials`, and `HttpResponsePreReturn`. In this example, `src/guard.rs` makes every decision, `src/http_legacy.rs` and `src/http_v2.rs` only translate it, and `router` in `src/main.rs` serves all three services. Each result carries the same reason, reason code, findings, and metadata under both protocols.

   | Guard result | Legacy request | Legacy response | Version 2 |
   | --- | --- | --- | --- |
   | No match | `Allow` without a body | `PassThrough` | `HttpBufferedResult` with `unchanged` |
   | Redacted | `Allow` with the redacted `body` | `Transform` | `HttpBufferedResult` with `replacement` |
   | Denied | `Deny` | `BlockDelivery` | `HttpReject` |
   | Bodyless response | Not applicable | gRPC error | `continue_without_body` at preflight |
   | Cannot inspect | gRPC error | gRPC error | gRPC error `FAILED_PRECONDITION` |

   Version 2 tells the service more than the legacy protocol does, so the guard behaves differently in two cases:

   - `HttpPreflight.unavailable_body_modes` says why OpenShell does not offer a body mode the binding supports. A bodyless response, such as the answer to a `HEAD` request or a 1xx, 204, or 304 response, has nothing to guard, so the guard lets it continue when the reason is `HTTP_BODY_UNAVAILABLE_REASON_BODYLESS`. For any other reason it cannot inspect the body and fails the stage. The legacy preflight gives no reason, so the legacy handler fails every response without `WHOLE_BODY_BYTES`, bodyless ones included, as v0.1.2 does.
   - OpenShell reports a version 2 stage that ends with `FAILED_PRECONDITION` as `middleware_cannot_inspect` instead of as a service error. The guard returns it only when it cannot inspect the message: OpenShell does not offer the complete body, or the body is not UTF-8. Errors such as an invalid configuration or an out-of-order event use `INVALID_ARGUMENT`. The legacy handlers keep the v0.1.2 status codes.

4. Choose body modes. The guard matches literal terms against a complete UTF-8 body, so it selects `BUFFERED` in both directions, the counterpart of `WHOLE_BODY_BYTES` and the legacy request RPC, with `max_body_bytes` set to the offered `max_buffered_body_bytes` capped by its own limit. It does not advertise `STREAM`: a streaming guard would carry partial terms and UTF-8 sequences across chunks, a deny after its first output would abort a response instead of returning a 403, and it would inspect oversized and `text/event-stream` bodies that the legacy protocol never sends, so the protocols would no longer behave the same.

5. Test both protocols. `src/protocol_tests.rs` serves the binary's services on loopback, sends each case through both protocols in OpenShell's event order, and asserts the same outcome and diagnostics, apart from the two differences above.

A gRPC error fails the stage under both protocols. With legacy bindings, the policy's `on_error` decides whether the exchange then fails open or closed; version 2 bindings always fail closed, with `middleware_cannot_inspect` for `FAILED_PRECONDITION`. OpenShell also fails closed when a service answers an RPC from its manifest with `UNIMPLEMENTED`. A dual-protocol build never does, so peers that described the service before an upgrade keep working.

Once every gateway and supervisor that uses the service advertises `http-v2`, and at the latest for OpenShell 0.2.0, drop the legacy protocol: delete `src/http_legacy.rs`, answer the legacy RPCs with `UNIMPLEMENTED` until the proto removes them, return version 2 bindings to every caller, and require `http-v2` with `extension_metadata_with_requirements`. Until OpenShell 0.2.0, the gateway rejects `on_error: fail_open` on entries that use a service that requires `http-v2`, including entries that keep it for a WebSocket binding.

## Prerequisites

Install `cargo`, `curl`, `jq`, `openssl`, `mise`, and `uv` with Python 3 on the host before running the smoke script. Start Docker or Podman. The supervisor image build uses the repository's Linux cross-compilation toolchain, including `cargo-zigbuild` and Zig on macOS. Install the repository's mise tools before running it.

## Run the smoke example

Run the end-to-end smoke suite to build a local gateway and sandbox supervisor, start the content-guard service, create a sandbox, and send the same request body to two destinations:

```shell
./examples/supervisor-middleware-content-guard/smoke.sh --test-suite
```

The first request goes to `httpbin.org`, which matches the middleware endpoint selector. The response contains `[FILTERED]` instead of `prototype-secret`. The second request goes to `httpbingo.org`, which is allowed by network policy but does not match the middleware selector. Its response contains the original `prototype-secret` value. The smoke suite asserts both results and cleans up the sandbox, gateway, and middleware processes.

Run the script without flags to leave the local stack running for interactive use:

```shell
./examples/supervisor-middleware-content-guard/smoke.sh
```

The script creates the sandbox and prints the guarded and unguarded request commands. Press Ctrl-C to clean up. The middleware service must be reachable from both the host gateway and sandbox containers. The script detects a non-loopback host address automatically; override it when necessary:

```shell
CONTENT_GUARD_SMOKE_HOST=192.168.1.10 ./examples/supervisor-middleware-content-guard/smoke.sh --test-suite
```

The script defaults to Docker. Set `CONTENT_GUARD_SMOKE_DRIVER=podman` to build and run with Podman instead.

On Linux and macOS, the script runs `mise run docker:build:supervisor` with the selected container engine to build a Linux supervisor from the current checkout. It configures that driver's `supervisor_image` with a unique local tag, so the response checks exercise the local runtime changes. macOS host binaries are never used inside the sandbox. The local image remains available after the smoke run.

Cargo's configured target directory applies to the host binaries and the Linux supervisor build. For example:

```shell
CARGO_TARGET_DIR=/tmp/content-guard-target ./examples/supervisor-middleware-content-guard/smoke.sh --test-suite
```

## Run manually

Start the service before starting the gateway. Bind to all host interfaces so a local containerized gateway and sandbox supervisor can reach it:

```shell
cd examples/supervisor-middleware-content-guard
cargo run -- --bind 0.0.0.0:50051
```

Add the service registration to your local gateway TOML:

```toml
[[openshell.supervisor.middleware]]
name = "content-guard-example"
grpc_endpoint = "http://host.openshell.internal:50051"
allow_insecure_transport = true
max_payload_bytes = 262144
timeout = "500ms"
```

The gateway calls `Describe` during startup and fails to start if the service is unavailable. Both the gateway and sandbox supervisors must resolve and reach the configured endpoint. Change the hostname when `host.openshell.internal` is not the shared host address for your local driver.

The `http://` gRPC endpoint uses plaintext without peer authentication.

The service manifest describes its supported operation and phase. The policy attaches the complete service by the operator-owned `content-guard-example` registration name, not by the diagnostic manifest name.

The `network_middlewares` map key `prototype-content-guard` is the stable policy-local identity. The optional `name` field is a human-readable label, and `order` must be unique across every middleware config in the policy.

## Apply the example policy

The included policy allows `curl` to POST to `https://httpbin.org/anything` and `https://httpbingo.org/anything`. Only `httpbin.org` matches the middleware selector, where the content guard replaces `prototype-secret` or `internal-only` in the request body:

```shell
openshell sandbox create --policy examples/supervisor-middleware-content-guard/policy.yaml
```

From the sandbox, send a matching request:

```shell
curl -sS https://httpbin.org/anything \
  --header 'content-type: application/json' \
  --data '{"note":"prototype-secret"}'
```

The echoed JSON body contains `[FILTERED]` instead of the configured term.

## HTTP response behavior

The smoke launcher starts the local fixture. To start it manually:

```shell
uv run --no-project python examples/supervisor-middleware-content-guard/upstream.py
```

The policy permits `GET /clean`, `GET /sensitive`, and `HEAD /sensitive` on
`http://host.openshell.internal:18081`. The first returns ordinary public text.
The second contains both configured terms. Redact mode returns
`contains [FILTERED] and [FILTERED]`. Deny mode returns `BlockDelivery` with
legacy bindings or `HttpReject` with version 2 bindings, with reason code
`content_match`, which produces the canonical 403 response before delivery. The
smoke suite recreates the sandbox in deny mode and checks both clean and
matching responses through the external gRPC service, and that the bodyless
`HEAD /sensitive` response passes. The smoke suite builds the gateway and
supervisor from the current checkout, which advertise `http-v2`, so it exercises
the version 2 bindings.

The guard inspects a selected response only with its complete body:
`WHOLE_BODY_BYTES` with legacy bindings and `BUFFERED` with version 2 bindings.
With version 2 bindings, a bodyless response, such as the answer to a `HEAD`
request or a 204 or 304 response, continues without inspection. Otherwise, when
OpenShell does not offer the complete body, the service returns a middleware
failure. This includes encoded, partial, no-transform, open-ended, and known
oversized responses, and bodyless responses with legacy bindings.
Unknown-length bodies can also exceed the runtime limit during collection.
Invalid UTF-8 fails the same way. With legacy bindings, the policy's `on_error`
decides whether delivery fails open or closed. Version 2 bindings always fail
closed, and OpenShell reports the guard's failure as `middleware_cannot_inspect`.
The example policy uses `fail_closed`.

Clean bodies pass unchanged. Matching spans are merged and replaced in the
complete body, so transport chunk boundaries do not affect matching. Trailers
are accepted without mutation. The guard does not decode compressed bodies,
normalize Unicode, scan response headers, retain stream units, or spool bodies.

## WebSocket behavior

For a selected WebSocket upgrade, the service accepts preflight, waits for the session-start notification, and evaluates each complete client-to-upstream text message. Redact mode returns a replacement message, while deny mode returns `content_match` and OpenShell closes the session according to middleware policy. Session-start and session-end events are notifications and do not produce results.

The service advertises a 256 KiB limit for complete WebSocket text messages. OpenShell does not send binary messages, control frames, or upstream-to-client messages to this binding. The smoke script exercises the HTTP path; the example's unit tests cover the WebSocket lifecycle and both redact and deny results.

## Configuration

| Field | Required | Description |
| --- | --- | --- |
| `mode` | No | `redact` (default) replaces matches; `deny` rejects the request. |
| `terms` | Yes | Non-empty list of non-empty, case-sensitive literal strings. Overlapping match ranges are merged before redaction. |
| `replacement` | No | Replacement text for `redact`; defaults to `[REDACTED]` and is invalid with `deny`. |

To exercise denial, change the policy config to:

```yaml
config:
  mode: deny
  terms:
    - prototype-secret
```

The implementation supports `HTTP_REQUEST/PRE_CREDENTIALS`, `HTTP_RESPONSE/PRE_RETURN`, and `WEBSOCKET_MESSAGE/PRE_CREDENTIALS`. It advertises a 256 KiB limit for each operation and inherits the service-wide RPC timeout. The gateway registration's `max_payload_bytes` may set a smaller shared limit. A binding can advertise a shorter timeout, but it cannot extend the operator-configured timeout.
