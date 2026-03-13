---
title:
  page: Gateway Authentication
  nav: Gateway Authentication
description: Gateway resolution, authentication modes, connection flow, and credential file layout.
topics:
- Generative AI
- Cybersecurity
tags:
- Gateway
- Authentication
- mTLS
- Edge Authentication
- Reference
content:
  type: reference
  difficulty: technical_intermediate
  audience:
  - engineer
---

<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Gateway Authentication

This page describes how the CLI resolves a gateway, authenticates with it, and where credentials are stored. For how to deploy or register gateways, refer to {doc}`/sandboxes/create-and-manage`.

## Gateway Resolution

When any CLI command needs to talk to the gateway, it resolves the target through a priority chain:

1. `--gateway-endpoint <URL>` flag (direct URL).
2. `-g <NAME>` flag.
3. `OPENSHELL_GATEWAY` environment variable.
4. Active gateway from `~/.config/openshell/active_gateway`.

The CLI loads gateway metadata from disk to determine the endpoint URL and authentication mode.

## Authentication Modes

The CLI uses one of three connection modes depending on the gateway's authentication configuration.

### mTLS (local and remote gateways)

The default mode for self-deployed gateways. When you run `gateway start` or `gateway add --local` / `gateway add --remote`, the CLI extracts mTLS certificates from the running container and stores them locally. Every subsequent request presents a client certificate to prove identity.

The CLI loads three PEM files from `~/.config/openshell/gateways/<name>/mtls/`:

| File | Purpose |
|---|---|
| `ca.crt` | CA certificate. Verifies the gateway's server certificate. |
| `tls.crt` | Client certificate. Proves the CLI's identity to the gateway. |
| `tls.key` | Client private key. |

The connection flow:

1. The CLI loads the three certificate files.
2. Opens a TCP connection to the gateway endpoint.
3. Performs a TLS handshake, presenting the client certificate.
4. The gateway verifies the client certificate against its CA.
5. An HTTP/2 channel is established. All CLI commands use this channel.

### Edge JWT (cloud gateways)

For gateways behind a reverse proxy that handles authentication (e.g. Cloudflare Access), the CLI uses a browser-based login flow and routes traffic through a WebSocket tunnel.

**Registration flow** (`openshell gateway add https://gateway.example.com`):

1. The CLI stores gateway metadata with the edge authentication mode.
2. Opens your browser to the gateway's authentication endpoint.
3. The reverse proxy handles login (SSO, identity provider, etc.).
4. After authentication, the browser relays the authorization token back to the CLI via a localhost callback.
5. The CLI stores the token and sets the gateway as active.

**Connection flow** (subsequent commands):

1. The CLI starts a local proxy that listens on an ephemeral port.
2. The proxy opens a WebSocket connection (`wss://`) to the gateway, attaching the stored bearer token in the upgrade headers.
3. The reverse proxy authenticates the WebSocket upgrade request.
4. The gateway bridges the WebSocket into the same service that handles direct mTLS connections.
5. CLI commands send requests through the local proxy as plaintext HTTP/2 over the tunnel.

This is transparent to the user. All CLI commands work the same regardless of whether the gateway uses mTLS or edge authentication.

**Re-authentication**: If the token expires, run `openshell gateway login` to open the browser flow again and update the stored token.

### Plaintext

When a gateway is deployed with `--plaintext`, TLS is disabled entirely. The CLI connects over plain HTTP/2. This mode is intended for gateways behind a trusted reverse proxy or tunnel that handles TLS termination externally.

## File Layout

All gateway credentials and metadata are stored under `~/.config/openshell/`:

```
openshell/
  active_gateway                    # Plain text: active gateway name
  gateways/
    <name>/
      metadata.json                 # Gateway metadata (endpoint, auth mode, type)
      mtls/                         # mTLS bundle (local and remote gateways)
        ca.crt                      # CA certificate
        tls.crt                     # Client certificate
        tls.key                     # Client private key
      edge_token                    # Edge auth JWT (cloud gateways)
      last_sandbox                  # Last-used sandbox for this gateway
```
