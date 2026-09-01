<!--
SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# HTTP Response Transform Middleware

> [!WARNING]
> Supervisor middleware is a research preview. Its policy and service contracts may change without compatibility guarantees. Use it only to prototype and evaluate middleware integrations.

This operator-run service demonstrates all three `HTTP_RESPONSE/PRE_RETURN` body modes. It selects a mode from the request path, changes one response header, and transforms the upstream response before the sandbox receives it.

| Path | Middleware mode | Result |
| --- | --- | --- |
| `/headers-only` | `HEADERS_ONLY` | Adds `x-example-response-mode` and passes the body through. |
| `/whole-body` | `WHOLE_BODY_BYTES` | Buffers the normalized body and prefixes it with `[whole]` plus a space. |
| `/stream` | `STREAM_BYTES` | Uppercases each normalized unit and writes the declared `x-example-body-bytes` trailer. |

Other paths return `SKIP` with the audit-safe reason code `path_not_selected`.

## Run the Example

Start the raw HTTP upstream. It deliberately returns one content-length response, one chunked response, and one close-delimited response:

```shell
python3 examples/supervisor-middleware-response-transform/upstream.py
```

In another terminal, start the middleware service. Bind to all host interfaces so a containerized gateway and sandbox supervisor can reach it:

```shell
cargo run \
  --manifest-path examples/supervisor-middleware-response-transform/Cargo.toml \
  -- \
  --bind 0.0.0.0:50052
```

Register the service in the gateway TOML, then start or restart the gateway:

```toml
[[openshell.supervisor.middleware]]
name = "response-transform-example"
grpc_endpoint = "http://host.openshell.internal:50052"
allow_insecure_transport = true
max_payload_bytes = 262144
timeout = "500ms"
```

The plaintext endpoint has no peer authentication. Use it only for this local example. Both the gateway and sandbox supervisors must resolve and reach the configured hostname.

Create a sandbox with the included policy:

```shell
openshell sandbox create \
  --policy examples/supervisor-middleware-response-transform/policy.yaml
```

Run these commands inside the sandbox:

```shell
curl -i http://host.openshell.internal:18081/headers-only
curl -i http://host.openshell.internal:18081/whole-body
curl -i --raw http://host.openshell.internal:18081/stream
```

The first response keeps the `headers-only` body unchanged. The second body becomes `[whole] whole body`. The third body becomes `STREAM BODY` and ends with `x-example-body-bytes: 11`.

OpenShell repairs framing after middleware runs. The content-length response selected for headers-only inspection is delivered with streaming-compatible chunked framing, the upstream chunked body selected for whole-body inspection receives a recalculated `Content-Length`, and the close-delimited stream is delivered as chunked with its declared trailer. Middleware receives normalized representation bytes, never upstream transfer chunks or socket-read boundaries.

## Test the Service

```shell
cargo test \
  --manifest-path examples/supervisor-middleware-response-transform/Cargo.toml \
  --all-targets
```
