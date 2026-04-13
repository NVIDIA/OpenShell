# Gateway Communication

## Overview

This document describes how the CLI resolves a gateway and communicates with it once the endpoint already exists. The gateway exposes gRPC and HTTP services on a single multiplexed port, and the CLI chooses one of three connection modes: direct mTLS, edge-authenticated WebSocket tunnel, or plaintext HTTP/2 behind a trusted proxy.

## Connection Flow

### Gateway resolution

When any CLI command needs to talk to the gateway, it resolves the target through a priority chain (`crates/openshell-cli/src/main.rs` -- `resolve_gateway()`):

1. `--gateway-endpoint <URL>` flag (direct URL, reusing stored metadata when the gateway is known).
2. `--gateway <NAME>` / `-g <NAME>` flag.
3. `OPENSHELL_GATEWAY` environment variable.
4. Active gateway from `~/.config/openshell/active_gateway`.

Resolution loads `GatewayMetadata` from disk to get the `gateway_endpoint` URL and `auth_mode`. When `--gateway-endpoint` is used, the CLI still tries to match the URL to stored metadata so edge auth tokens and TLS bundles continue to resolve by gateway name.

### Connection modes

```mermaid
graph TD
    CLI["CLI Command"]
    RESOLVE["Resolve Gateway"]
    MODE{"auth_mode?"}

    MTLS["mTLS Channel"]
    EDGE["Edge Tunnel"]
    PLAIN["Plaintext Channel"]

    GW["Gateway (gRPC + HTTP)"]

    CLI --> RESOLVE
    RESOLVE --> MODE

    MODE -->|"null / mtls"| MTLS
    MODE -->|"cloudflare_jwt"| EDGE
    MODE -->|"plaintext"| PLAIN

    MTLS -->|"TLS + client cert"| GW
    EDGE -->|"WSS tunnel + JWT"| GW
    PLAIN -->|"HTTP/2 plaintext"| GW
```

### mTLS connection (default)

**File**: `crates/openshell-cli/src/tls.rs` -- `build_channel()`

The default mode for self-deployed gateways. The CLI loads three PEM files from `~/.config/openshell/gateways/<name>/mtls/`:

| File      | Purpose                                                        |
| --------- | -------------------------------------------------------------- |
| `ca.crt`  | Gateway CA certificate -- verifies the gateway's server cert   |
| `tls.crt` | Client certificate -- proves the CLI's identity to the gateway |
| `tls.key` | Client private key                                             |

These are used to build a `tonic::transport::ClientTlsConfig`, which configures a `tonic::transport::Channel` for gRPC communication over HTTP/2 with mTLS.

```mermaid
sequenceDiagram
    participant CLI as CLI
    participant GW as Gateway

    CLI->>CLI: Load ca.crt, tls.crt, tls.key
    CLI->>GW: TCP connect to gateway_endpoint
    CLI->>GW: TLS handshake (present client cert)
    GW->>GW: Verify client cert against CA
    GW-->>CLI: TLS established (HTTP/2 via ALPN)
    CLI->>GW: gRPC requests (OpenShell / Inference service)
```

### Edge-authenticated connection

**Files**: `crates/openshell-cli/src/edge_tunnel.rs`, `crates/openshell-cli/src/auth.rs`

For gateways behind an edge proxy (e.g., Cloudflare Access), the CLI routes traffic through a local WebSocket tunnel proxy:

1. `start_tunnel_proxy()` binds an ephemeral local TCP port.
2. Opens a WebSocket connection (`wss://<gateway>/_ws_tunnel`) to the edge with the stored bearer token in headers.
3. The gateway's `ws_tunnel.rs` handler upgrades the WebSocket and bridges it to an in-memory `MultiplexService` instance.
4. The gRPC channel connects to `http://127.0.0.1:<local_port>` (plaintext HTTP/2 over the tunnel).

Authentication uses a browser-based flow: `gateway add` opens the user's browser to the gateway's `/auth/connect` endpoint, which reads the `CF_Authorization` cookie and relays it back to a localhost callback server. The token is stored at `~/.config/openshell/gateways/<name>/edge_token`.

### Plaintext connection

When the gateway is deployed with `--plaintext`, TLS is disabled entirely. The CLI connects over plain HTTP/2. This mode is intended for gateways behind a trusted reverse proxy or tunnel that handles TLS termination.

The CLI also treats an explicit `http://...` registration as plaintext mode:

```shell
openshell gateway add http://127.0.0.1:8080 --local
```

This stores `auth_mode = "plaintext"`, skips mTLS certificate extraction, and bypasses the edge browser-auth flow.

## File System Layout

All connection artifacts are stored under `$XDG_CONFIG_HOME/openshell/` (default `~/.config/openshell/`):

```
openshell/
  active_gateway                          # plain text: active gateway name
  gateways/
    <name>/
      metadata.json                       # GatewayMetadata JSON
      mtls/                               # mTLS bundle (when TLS enabled)
        ca.crt                            # gateway CA certificate
        tls.crt                           # client certificate
        tls.key                           # client private key
      edge_token                          # Edge auth JWT (when auth_mode=cloudflare_jwt)
```

## Registering an Edge-Authenticated Gateway

For gateways that are already deployed behind an edge proxy (e.g., Cloudflare Access), deployment is not needed -- only registration.

**File**: `crates/openshell-cli/src/run.rs` -- `gateway_add()`

```mermaid
sequenceDiagram
    participant U as User
    participant CLI as openshell-cli
    participant Browser as Browser
    participant Edge as Edge Proxy
    participant GW as Gateway

    U->>CLI: openshell gateway add https://gw.example.com
    CLI->>CLI: Store metadata (auth_mode: cloudflare_jwt)
    CLI->>Browser: Open https://gw.example.com/auth/connect
    Browser->>Edge: Edge proxy login
    Edge-->>Browser: CF_Authorization cookie
    Browser->>GW: GET /auth/connect (with cookie)
    GW-->>Browser: Relay page (extracts token, POSTs to localhost)
    Browser->>CLI: POST token to localhost callback
    CLI->>CLI: Store edge_token
    CLI->>CLI: save_active_gateway
    CLI-->>U: Gateway added and set as active
```
