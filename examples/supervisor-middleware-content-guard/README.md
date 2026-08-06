<!--
SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Supervisor Middleware Content Guard

> [!WARNING]
> Supervisor middleware is a research preview. Its policy and service contracts may change without compatibility guarantees. Use it only to prototype and evaluate middleware integrations.

This example implements an authenticated, operator-run supervisor middleware service. It serves gRPC over TLS, verifies gateway-minted EdDSA JWTs against a provisioned gateway JWKS document, and scans UTF-8 HTTP request bodies for configured literal strings. It then either replaces every match or denies the request. Findings report only aggregate counts and never include configured terms or request content.

> [!WARNING]
> This intentionally simple implementation demonstrates the supervisor middleware service contract. It is not a complete or reliable content guard and must not be used as a security control. It handles only UTF-8 request bodies and case-sensitive literal terms, merges overlapping literal match ranges before redaction, and does not address the encodings, transformations, normalization, streaming, or adversarial inputs that a production content guard must handle.

## Prerequisites

Install `cargo`, `curl`, `jq`, and `openssl` on the host before running the smoke script.

## Run the smoke example

Run the end-to-end smoke suite to build and start a local gateway, start the content-guard service, create a sandbox, and send the same request body to two destinations:

```shell
./examples/supervisor-middleware-content-guard/smoke.sh --test-suite
```

The script generates a local gateway signing key and middleware CA, provisions the gateway public key to the middleware as JWKS, and configures the gateway to trust the middleware CA. The first request goes to `httpbin.org`, which matches the middleware endpoint selector. The response contains `[FILTERED]` instead of `prototype-secret`. The second request goes to `httpbingo.org`, which is allowed by network policy but does not match the middleware selector. Its response contains the original `prototype-secret` value. The smoke suite asserts both results and cleans up the sandbox, gateway, and middleware processes.

Run the script without flags to leave the local stack running for interactive use:

```shell
./examples/supervisor-middleware-content-guard/smoke.sh
```

The script creates the sandbox and prints the guarded and unguarded request commands. Press Ctrl-C to clean up. The middleware service must be reachable from both the host gateway and sandbox containers. The script detects a non-loopback host address automatically; override it when necessary:

```shell
CONTENT_GUARD_SMOKE_HOST=192.168.1.10 ./examples/supervisor-middleware-content-guard/smoke.sh --test-suite
```

## Run manually

Provision these values before starting the service:

- A TLS certificate and private key for the middleware endpoint.
- The CA bundle that gateway and supervisor clients use to verify that certificate.
- A trusted copy of the gateway JWKS document, available from `https://<gateway>/.well-known/jwks.json` on an already-running trusted gateway.
- The gateway issuer, `openshell-gateway:<gateway-id>`.
- The exact audience configured for the middleware registration.

The JWKS document is public, but it is not a trust root by itself. Obtain it through an authenticated gateway connection or provision it through the same trusted configuration channel as the issuer and audience. A new gateway calls middleware `Describe` before its own HTTP listener starts, so initial bootstrap cannot depend only on that same gateway's JWKS endpoint.

Start the service before starting the gateway. Bind to all host interfaces so a local containerized gateway and sandbox supervisor can reach it:

```shell
cd examples/supervisor-middleware-content-guard
cargo run -- \
  --bind 0.0.0.0:50051 \
  --tls-cert /run/content-guard/tls.crt \
  --tls-key /run/content-guard/tls.key \
  --gateway-jwks /run/content-guard/gateway-jwks.json \
  --gateway-issuer openshell-gateway:local-dev \
  --audience urn:openshell:extension:middleware:content-guard-example
```

Add the service registration to your local gateway TOML:

```toml
[[openshell.supervisor.middleware]]
name = "content-guard-example"
grpc_endpoint = "https://host.openshell.internal:50051"
tls_ca_cert_path = "/run/content-guard/ca.crt"
audience = "urn:openshell:extension:middleware:content-guard-example"
max_body_bytes = 262144
timeout = "500ms"
```

The gateway calls `Describe` during startup and fails to start if the service is unavailable. Both the gateway and sandbox supervisors must resolve and reach the configured endpoint. Change the hostname when `host.openshell.internal` is not the shared host address for your local driver.

The gateway and supervisors verify the middleware certificate against `tls_ca_cert_path`, including normal hostname verification. The middleware verifies the bearer token signature, `kid`, EdDSA algorithm, issuer, audience, expiry, maximum lifetime, and caller identity shape. It then authorizes caller kinds by RPC:

| RPC | Accepted caller |
| --- | --- |
| `Describe` | Gateway or sandbox supervisor |
| `ValidateConfig` | Gateway only |
| `EvaluateHttpRequest` | Sandbox supervisor only |

The service returns `Unauthenticated` for missing or invalid credentials and `PermissionDenied` when a valid caller kind invokes an RPC it is not allowed to use. Unknown `kid` values require replacing the provisioned JWKS document and restarting this alpha example; production integrations should cache keys and refresh from the trusted gateway JWKS URL on an unknown `kid`.

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

The implementation supports only `HttpRequest/pre_credentials`, advertises a 256 KiB body limit, and inherits the service-wide RPC timeout. The gateway registration may set a smaller body limit. A binding can advertise a shorter timeout, but it cannot extend the operator-configured timeout.
