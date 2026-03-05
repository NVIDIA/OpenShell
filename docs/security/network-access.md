<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Network Access Control

The `network_policies` section of a sandbox policy controls which remote hosts each program in the sandbox can connect to, preventing unauthorized data exfiltration. The proxy evaluates every outbound connection against these rules — no data leaves the sandbox without explicit authorization.

## Basic Structure

Network policies are a map of named entries. Each entry specifies endpoints (host + port) and the binaries allowed to connect to them:

```yaml
network_policies:
  github:
    endpoints:
      - host: github.com
        port: 443
      - host: api.github.com
        port: 443
    binaries:
      - path_patterns: ["**/git"]
      - path_patterns: ["**/ssh"]

  anthropic:
    endpoints:
      - host: api.anthropic.com
        port: 443
    binaries:
      - path_patterns: ["**/claude"]
      - path_patterns: ["**/node"]
```

## Endpoints

Each endpoint specifies a host and port:

```yaml
endpoints:
  - host: api.example.com
    port: 443
```

The `host` field matches the hostname in the CONNECT request. The `port` field matches the destination port.

## Binary Matching

The `binaries` field specifies which programs are allowed to connect to the endpoints. Each binary entry uses glob patterns matched against the full path of the executable:

```yaml
binaries:
  - path_patterns: ["**/git"]           # matches /usr/bin/git, /usr/local/bin/git, etc.
  - path_patterns: ["**/node"]          # matches any 'node' binary
  - path_patterns: ["/usr/bin/curl"]    # matches only this specific path
```

### Binary Integrity

The proxy uses a trust-on-first-use (TOFU) model for binary verification. The first time a binary makes a network request, its SHA256 hash is recorded. If the binary changes later (indicating possible tampering), subsequent requests are denied.

## L7 Inspection

For endpoints that need deeper inspection, you can configure L7 (HTTP-level) rules. L7 inspection terminates TLS and inspects individual HTTP requests:

```yaml
network_policies:
  api-service:
    endpoints:
      - host: api.example.com
        port: 443
        l7:
          tls_mode: terminate
          enforcement_mode: enforce
          rules:
            - method: GET
              path_pattern: "/v1/data/*"
            - method: POST
              path_pattern: "/v1/submit"
    binaries:
      - path_patterns: ["**/curl"]
```

### L7 Fields

| Field | Description |
|-------|-------------|
| `tls_mode` | `terminate` — proxy terminates TLS and inspects plaintext HTTP. |
| `enforcement_mode` | `enforce` — block requests that don't match any rule. `audit` — log violations but allow traffic. |
| `rules` | List of allowed HTTP method + path patterns. |

### Access Presets

Instead of listing individual rules, you can use an `access` preset:

```yaml
network_policies:
  api-service:
    endpoints:
      - host: api.example.com
        port: 443
        l7:
          tls_mode: terminate
          access: read-only
    binaries:
      - path_patterns: ["**/curl"]
```

| Preset | Allowed Methods |
|--------|----------------|
| `read-only` | `GET`, `HEAD`, `OPTIONS` |
| `read-write` | `GET`, `HEAD`, `OPTIONS`, `POST`, `PUT`, `PATCH`, `DELETE` |
| `full` | All HTTP methods |

Presets are expanded into explicit rules at policy load time.

## SSRF Protection

Even when a hostname is allowed by policy, the proxy resolves DNS before connecting and blocks any result that points to a private network address. This prevents SSRF attacks where an allowed hostname could be redirected to internal infrastructure.

Blocked IP ranges include:

- Loopback (`127.0.0.0/8`, `::1`)
- RFC 1918 private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
- Link-local (`169.254.0.0/16`, `fe80::/10`)
- Cloud metadata endpoints (e.g., `169.254.169.254`)

## Network Modes

The sandbox supports three network modes, determined at creation time:

| Mode | Description |
|------|-------------|
| **Proxy** | All traffic goes through the policy-enforcing proxy. Activated when `network_policies` is non-empty. |
| **Block** | No network access at all. System calls for network sockets are blocked by seccomp. |
| **Allow** | Unrestricted network access. No proxy, no seccomp filtering. |

The network mode cannot change after sandbox creation. Adding `network_policies` to a sandbox created without them (or removing all policies from a sandbox that has them) is rejected.

## Tri-State Routing Decision

When a connection request arrives at the proxy, the OPA engine returns one of three actions:

| Action | Condition | Behavior |
|--------|-----------|----------|
| **Allow** | Endpoint + binary matched a `network_policies` entry. | Connection proceeds directly. |
| **Inspect for Inference** | No policy match, but `inference.allowed_routes` is non-empty. | TLS-terminate and check for inference API patterns. See [Inference Routing](../inference/index.md). |
| **Deny** | No match and no inference routing configured. | Connection is rejected. |
