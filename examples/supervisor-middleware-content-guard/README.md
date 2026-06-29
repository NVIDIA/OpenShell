<!--
SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Supervisor Middleware Content Guard

<!-- markdownlint-disable MD033 -->
<Warning title="Research Preview Feature">
Supervisor middleware is a research preview. Its policy and service contracts may change without compatibility guarantees. Use it only to prototype and evaluate middleware, not for production or long-lived integrations.
</Warning>
<!-- markdownlint-enable MD033 -->

This example implements the `example/content-guard` supervisor middleware binding. It scans UTF-8 HTTP request bodies for configured literal strings, then either replaces every match or denies the request. Findings report only aggregate counts and never include configured terms or request content.

## Run the service

Start the service before starting the gateway. Bind to all host interfaces so a local containerized gateway and sandbox supervisor can reach it:

```shell
cd examples/supervisor-middleware-content-guard
cargo run -- --bind 0.0.0.0:50051
```

Add the service registration to your local gateway TOML:

```toml
[[openshell.gateway.middleware]]
name = "content-guard-example"
endpoint = "http://host.openshell.internal:50051"
allow_insecure = true
max_body_bytes = 262144
```

The gateway calls `Describe` during startup and fails to start if the service is unavailable. Both the gateway and sandbox supervisors must resolve and reach the configured endpoint. Change the hostname when `host.openshell.internal` is not the shared host address for your local driver.

The plaintext endpoint has no transport encryption or peer authentication. `allow_insecure = true` is an explicit acknowledgement of that limitation.

## Apply the example policy

The included policy allows `curl` to POST to `https://httpbin.org/anything` and replaces `prototype-secret` or `internal-only` in the request body:

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

## Configuration

| Field | Required | Description |
| --- | --- | --- |
| `mode` | No | `redact` (default) replaces matches; `deny` rejects the request. |
| `terms` | Yes | Non-empty list of non-empty, case-sensitive literal strings. |
| `replacement` | No | Replacement text for `redact`; defaults to `[REDACTED]` and is invalid with `deny`. |

To exercise denial, change the policy config to:

```yaml
config:
  mode: deny
  terms:
    - prototype-secret
```

The implementation supports only `HttpRequest/pre_credentials` and advertises a 256 KiB body limit. The gateway registration may set a smaller operator limit.
