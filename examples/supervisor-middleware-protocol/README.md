<!--
SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Supervisor middleware protocol example

This standalone gRPC service demonstrates all current V1 hooks:
`HTTP_REQUEST/PRE_CREDENTIALS`, `HTTP_RESPONSE/PRE_RETURN`, and
`WEBSOCKET_MESSAGE/PRE_CREDENTIALS`. Supervisor middleware is a research preview.

The example selects canned behavior by path. For configured literal matching,
use [content guard](../supervisor-middleware-content-guard/) instead.

## Run

Install Cargo, curl, jq, OpenSSL, and uv with Python 3. A local Docker or Podman
runtime must support OpenShell sandboxes.

```shell
./examples/supervisor-middleware-protocol/smoke.sh --test-suite
```

The launcher builds the gateway, supervisor, CLI, and middleware, starts the
local fixture on port 18081, and creates a sandbox with the included policy.
It checks each behavior below and removes its sandbox and processes on exit.
The fixture port must be free. Run the two middleware examples sequentially.

Run without flags to keep the stack running. Use `PROTOCOL_SMOKE_HOST` to
override the detected non-loopback IPv4 address and `PROTOCOL_SMOKE_DRIVER`
to select `docker` or `podman`. Both the gateway and sandbox must reach the
service endpoint. `--print-config` prints the generated gateway registration.

For manual startup:

```shell
cargo run --manifest-path examples/supervisor-middleware-protocol/Cargo.toml -- --bind 0.0.0.0:50051
uv run --no-project python examples/supervisor-middleware-protocol/upstream.py
```

Register the service before starting the gateway:

```toml
[[openshell.supervisor.middleware]]
name = "protocol-example"
grpc_endpoint = "http://host.openshell.internal:50051"
allow_insecure_transport = true
max_payload_bytes = 262144
timeout = "500ms"
```

The endpoint uses plaintext without peer authentication for local development.
Adjust its hostname to an address reachable from the gateway and sandbox.
The service takes empty configuration and advertises a 256 KiB payload limit.

## Behaviors

All routes use `http://host.openshell.internal:18081`.

| Route | Hook and behavior |
| --- | --- |
| `POST /request` | Request hook uppercases ASCII bytes; the fixture echoes the changed body. |
| `GET /headers-only` | Response hook adds `x-example-response-mode: headers-only` and preserves content-length framing. |
| `GET /whole-body` | Selects `WHOLE_BODY_BYTES` and prefixes the normalized chunked body with `[whole]`. |
| `GET /stream` | Selects `STREAM_BYTES`, uppercases each unit, and overwrites the supplied `x-example-body-bytes` trailer with `11`. |
| `GET /stream-close` | Uppercases a close-delimited event-stream response. |
| `GET /block` | Blocks the complete body before commitment with typed `BlockDelivery` and reason code `content_match`. |
| `GET /ws` upgrade | WebSocket hook uppercases each complete client text message; the fixture echoes it. |

The smoke suite checks the canonical 403 for `/block`. Other response paths
return `Skip`, including the request echo path. Request bodies outside
`/request` pass unchanged.

Stream transformations act only on the current unit. Unit boundaries have no
application meaning, so this example neither matches cross-unit terms nor
retains bytes for a future result. Header-only inspection preserves transport
framing. Body modes receive normalized bytes and finish with a trailer exchange,
including an empty trailer set. Selecting an unavailable mode returns a
middleware failure, handled by the policy's `fail_closed` setting.

WebSocket preflight chooses inspection, session start/end are notifications,
and each message result echoes its sequence number. Only client text messages
are inspected. Binary, control, and upstream messages are outside this hook.
The fixture and client perform one text exchange; they are not general WebSocket
implementations.

## Source and tests

`src/request.rs`, `src/response.rs`, and `src/websocket.rs` own their hook
behavior. `src/main.rs` owns startup, the manifest, and empty configuration
validation. The policy selects this service by the operator registration
`protocol-example`.

```shell
cargo test --manifest-path examples/supervisor-middleware-protocol/Cargo.toml
bash -n examples/supervisor-middleware-protocol/smoke.sh
```

Malformed framing, HTTP/1.0 edge cases, timeouts, disconnects, and security
boundary tests belong in the runtime crates.
