<!--
SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Sandbox application proxy

`openshell-sandbox-proxy` is an optional consumer of the gateway service discovery
API. It selects the exact discovered hostname from TLS SNI and forwards TLS bytes
to the owning supervisor's app listener. Application certificates and private
keys remain at supervisors. HTTP, WebSockets, application authentication, and
sandbox policy remain enforced by the existing listener and application.

```shell
openshell-sandbox-proxy \
  --gateway-endpoint https://gateway.example.com \
  --workspace default \
  --gateway-ca /run/discovery/ca.crt \
  --discovery-token-file /run/discovery/token \
  --listen-address 0.0.0.0:8443
```

Repeat `--workspace` for a finite set (up to 64 distinct names), or use
`--all-workspaces` to include every active workspace, including future ones.
These modes are mutually exclusive. For example:

```shell
openshell-sandbox-proxy --gateway-endpoint https://gateway.example.com \
  --workspace team-a --workspace team-b \
  --discovery-client-cert /run/discovery/tls.crt \
  --discovery-client-key /run/discovery/tls.key --gateway-ca /run/discovery/ca.crt
```

Use a discovery-only `OU=discovery` certificate with an administrator-managed
fingerprint grant, or an existing identity authorized for the selection. Client mTLS can
use `--discovery-client-cert` and `--discovery-client-key`. Credentials and CA
files reload on reconnect. The gateway must authorize every selected workspace;
a finite grant cannot request platform scope. Unauthorized selections fail as a
whole. All-workspaces output is bounded by the gateway's 64-workspace scan and
shared route/byte limits. The proxy does not require operator credentials. Plaintext
credential-free loopback development requires `--allow-insecure-gateway`.

A snapshot initializes the cache and bounded watches replace it. Reconnects
relist; transient errors retain routes only until their published expiry.
Authorization/configuration/data-integrity failures clear the cache. Monotonic
local deadlines are derived from absolute expiries and capped at fifteen seconds;
operators must synchronize gateway and proxy clocks. Snapshot revisions are
opaque and installation versions identify replacement independently of renewal.

Only exact, current routes can dial a backend. A route withdrawal, installation
replacement, or expiry closes affected TCP streams; renewal preserves them.
There is no gateway payload fallback, wildcard route fallback, or caller-selected
backend. Limits are 4,096 cached routes, 1,024 concurrent connections, 64 per
hostname, a 64 KiB ClientHello, and five-second hello/connect/setup deadlines.
Each relay uses Tokio's bounded bidirectional copy buffers. ClientHello parsing
is dependency-owned rustls protocol parsing, not a first-party cryptographic
operation. Authenticated discovery transport uses the shared SDK/crypto facade.

The health listener defaults to port 9091: `/healthz` is process liveness,
`/readyz` reflects discovery availability, and `/metrics` exposes connection
counts. During transient discovery failures readiness fails while existing
unexpired connections can continue. Expiry still closes streams independently
of the discovery connection. Multiple replicas keep independent caches and need
no Kubernetes ownership or leader election.

Build with `mise run docker:build:sandbox-proxy`. The standalone Helm chart at
`deploy/helm/openshell-sandbox-proxy` mounts only discovery identity/trust Secrets;
it needs no Kubernetes API permissions. Configure NetworkPolicy to allow the
proxy to reach the gateway API and discovered supervisor app endpoints, and
restrict supervisor ingress where edge authentication is required. The proxy
never authenticates application users using its discovery identity.

For Gateway API TLS passthrough, attach a TLSRoute to a Gateway listener in
`Passthrough` mode and target the proxy Service on port 443. Application TLS
terminates at the supervisor. An HTTPRoute requires a separate edge termination
and backend-TLS contract. A controller can instead consume the same discovery
API and reconcile exact-host routes directly to supervisor endpoints; it does
not need this proxy.

## Verification

```shell
cargo test -p openshell-sandbox-proxy
cargo clippy -p openshell-sandbox-proxy --all-targets -- -D warnings
helm lint deploy/helm/openshell-sandbox-proxy \
  --set gatewayEndpoint=https://gateway.example.com --set workspace=default
```

Kubernetes discovery resolves dedicated supervisors and acknowledged shared-pool
owners. During HA takeover the proxy withdraws the old installation and connects
to the new owner after it advertises an accepted installation. Existing streams
may close; clients reconnect without restarting the sandbox. Readable and hashed
hostnames use the same discovery path. The proxy consumes returned hostnames
and never reconstructs them or needs the gateway's hashing configuration.
