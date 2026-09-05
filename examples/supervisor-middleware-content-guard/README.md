<!--
SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Supervisor Middleware Content Guard

> [!WARNING]
> Supervisor middleware is a research preview. Its policy and service contracts may change without compatibility guarantees. Use it only to prototype and evaluate middleware integrations.

This example implements request, response, and client WebSocket bindings in one operator-run supervisor middleware service. The response binding demonstrates header-only inspection, whole-body and streaming transforms, trailer mutation, and block delivery.

> [!WARNING]
> This intentionally simple implementation demonstrates the supervisor middleware service contract. It is not a complete or reliable content guard and must not be used as a security control. It handles only UTF-8 HTTP request bodies and WebSocket text messages with case-sensitive literal terms, merges overlapping literal match ranges before redaction, and does not address encodings, transformations, normalization, binary WebSocket messages, upstream-to-client messages, or adversarial inputs that a production content guard must handle.

## Prerequisites

Install `cargo`, `curl`, `jq`, `openssl`, and Python 3 on the host before running the smoke script.

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

The gateway auto-detects its compute driver. Set `CONTENT_GUARD_SMOKE_DRIVER=docker` or `CONTENT_GUARD_SMOKE_DRIVER=podman` if more than one local runtime is installed and auto-detection selects the wrong one.

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

Start the included raw HTTP upstream in another terminal:

```shell
python3 examples/supervisor-middleware-content-guard/upstream.py
```

From the sandbox, exercise the response protocol:

```shell
curl -i http://host.openshell.internal:18081/headers-only
curl -i http://host.openshell.internal:18081/whole-body
curl -i --raw http://host.openshell.internal:18081/stream
curl -i --raw http://host.openshell.internal:18081/stream-close
curl -i http://host.openshell.internal:18081/block
```

| Path | Mode | Result |
| --- | --- | --- |
| `/headers-only` | `HEADERS_ONLY` | Adds `x-example-response-mode` without changing content-length framing. |
| `/whole-body` | `WHOLE_BODY_BYTES` | Prefixes the normalized body with `[whole]`. |
| `/stream` | `STREAM_BYTES` | Uppercases normalized units and changes the existing `x-example-body-bytes` trailer to `11`. |
| `/stream-close` | `STREAM_BYTES` | Uppercases a close-delimited `text/event-stream` response. |
| `/block` | `WHOLE_BODY_BYTES` | Returns OpenShell's canonical 403 response with reason code `content_match`. |

The upstream deliberately uses content-length, chunked, and close-delimited responses. OpenShell normalizes transport framing only for body-processing modes and validates trailer changes against the names supplied by the upstream.

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
