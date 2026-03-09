<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Network Access Rules

Every outbound connection from a sandbox passes through OpenShell's transparent
proxy. Nothing leaves the sandbox directly. The proxy identifies which binary
initiated the connection, evaluates the active policy, and decides what happens
next.

## How the Proxy Evaluates Connections

Each outbound connection resolves to one of three outcomes:

| Outcome                | When it applies                                                              | What happens                                                                 |
|------------------------|-----------------------------------------------------------------------------|-----------------------------------------------------------------------------|
| Allow              | A `network_policies` entry matches the destination host *and* the calling binary. | Traffic flows directly to the destination. The agent's own API key is used. |
| InspectForInference| No network policy matches, but `inference.allowed_routes` is configured.     | The proxy intercepts the connection and hands it to the privacy router, which reroutes it to a configured backend. The route's API key is used. |
| Deny               | No network policy matches and no inference route applies.                    | The connection is blocked. The calling process receives a 403 or connection reset. |

:::{note}
This is the most important distinction in OpenShell's network model.

*Agent traffic* is the coding agent (Claude, OpenCode, Codex) calling its own API to get completions. This traffic matches a `network_policies` entry because the policy declares both the endpoint (for example, `api.anthropic.com:443`) and the binary (for example, `/usr/local/bin/claude`). The proxy allows it through directly. The agent's own API key (injected by the provider) is used as-is.

*Userland traffic* is code that the agent *writes* making inference calls. A Python script calling the OpenAI-compatible API, a data pipeline hitting an LLM endpoint, a test harness querying a model. This traffic does *not* match any network policy because the calling binary (`/usr/bin/python3`) is not listed in the agent's policy entry. The proxy intercepts it, the privacy router reroutes it to a configured backend, and the route's API key is substituted in. The agent's code never touches your real API key.
:::

```{mermaid}
flowchart TD
    A["Outbound connection from sandbox"] --> B["Proxy resolves calling binary\n(/proc/pid/exe, ancestors, cmdline)"]
    B --> C{"Network policy matches\n(endpoint + binary)?"}
    C -- Yes --> D["Allow: forward directly\nto destination"]
    C -- No --> E{"Inference routes\nconfigured?"}
    E -- Yes --> F["InspectForInference:\nTLS terminate, check for\ninference pattern"]
    F --> G{"Matches inference\npattern?"}
    G -- Yes --> H["Route to configured\ninference backend"]
    G -- No --> I["Deny: 403"]
    E -- No --> I

    style A fill:#ffffff,stroke:#000000,color:#000000
    style B fill:#76b900,stroke:#000000,color:#000000
    style C fill:#76b900,stroke:#000000,color:#000000
    style D fill:#76b900,stroke:#000000,color:#000000
    style E fill:#76b900,stroke:#000000,color:#000000
    style F fill:#76b900,stroke:#000000,color:#000000
    style G fill:#76b900,stroke:#000000,color:#000000
    style H fill:#76b900,stroke:#000000,color:#000000
    style I fill:#ff4444,stroke:#000000,color:#ffffff

    linkStyle default stroke:#76b900,stroke-width:2px
```

## Structure of a Network Policy Entry

Each entry in the `network_policies` section pairs a set of endpoints with a set of binaries. Only the listed binaries can connect to the listed endpoints:

```yaml
network_policies:
  my_rule:
    name: my-rule
    endpoints:
      - host: api.example.com
        port: 443
        protocol: rest
        tls: terminate
        enforcement: enforce
        access: full
    binaries:
      - path: /usr/local/bin/my-agent
```

The key (`my_rule`) is a logical name for reference. The `name` field is the human-readable label that appears in logs and the OpenShell Terminal.

## Endpoints

Each endpoint entry controls access to a single host-port combination. Refer to [Endpoint Object](../reference/policy-schema.md#endpoint-object) for the full field reference.

The `access` field provides presets: `full` (all methods), `read-only` (`GET`, `HEAD`, `OPTIONS`), or `read-write` (`GET`, `HEAD`, `OPTIONS`, `POST`, `PUT`, `PATCH`).

### Custom Rules

When access presets are not granular enough, define explicit allow rules. Each rule specifies a method and a path pattern:

```yaml
endpoints:
  - host: github.com
    port: 443
    protocol: rest
    tls: terminate
    enforcement: enforce
    rules:
      - allow:
          method: GET
          path: /**/info/refs*
      - allow:
          method: POST
          path: /**/git-upload-pack
```

This example allows Git fetch operations (read-only clone and pull) while blocking push operations. Path patterns use glob syntax.

If a request does not match any rule, it is denied (in `enforce` mode) or logged (in `audit` mode).

## Binaries

The `binaries` list specifies which executables are permitted to use the endpoint. Each entry has a `path` field that the proxy matches against the calling process.

The proxy resolves the calling binary through several mechanisms, evaluated in order:

| Match type        | Example | Description |
|-------------------|---------|-------------|
| Exact path        | `/usr/local/bin/claude` | Matches the binary at exactly this path. |
| Ancestor process  | `/usr/local/bin/claude` | Matches if any ancestor in the process tree has this path. A Node.js subprocess spawned by Claude matches a `claude` entry. |
| Cmdline path      | `/usr/local/bin/opencode` | Matches against `/proc/pid/cmdline` for interpreted languages where the `exe` link points to the interpreter. |
| Glob pattern      | `/sandbox/.vscode-server/**` | Matches any executable under the directory tree. |

```yaml
binaries:
  - path: /usr/local/bin/claude
  - path: /usr/bin/node
  - path: /sandbox/.vscode-server/**
```

## L7 Inspection

To inspect HTTPS traffic at the HTTP level, you need both `protocol: rest` and `tls: terminate` on the endpoint:

```yaml
endpoints:
  - host: api.example.com
    port: 443
    protocol: rest
    tls: terminate
    enforcement: enforce
    access: full
```

With both fields set, the proxy terminates the TLS connection, decrypts the HTTP request, evaluates it against the `access` preset or custom `rules`, and re-encrypts before forwarding to the destination.

:::{warning}
Without `tls: terminate` on port 443, the proxy cannot decrypt the traffic. L7 rules (`access`, `rules`) are not evaluated because the HTTP payload is encrypted. The connection is handled at L4 only: allowed or denied based on host and port, with no HTTP-level access control.
:::

### Bare Endpoints (L4-Only)

Endpoints declared without `protocol` or `tls` are L4-only:

```yaml
endpoints:
  - host: registry.npmjs.org
    port: 443
```

The proxy allows the TCP connection through to the destination without decrypting or inspecting the payload. Use L4-only entries for non-HTTP traffic, package registries where you need connectivity but not method-level control, or endpoints where TLS termination is not desired.

:::{warning}
With L4-only rules, you have no control over *what* is sent to the endpoint: only *whether* the connection is allowed. Any binary listed in the entry can send any data to the host. If you need to restrict HTTP methods or paths, add `protocol: rest` and `tls: terminate`.
:::

## Forward Proxy Mode

The sandbox proxy supports two request modes: CONNECT tunnels (the default for
HTTPS) and forward proxy (for plain HTTP to private endpoints).

When a client inside the sandbox sets `HTTP_PROXY` and makes a plain `http://`
request, standard HTTP libraries send a forward proxy request instead of a
CONNECT tunnel. The proxy handles these transparently.

### Security Constraints

Forward proxy mode is restricted to private IP endpoints that are explicitly
allowed by policy. Plain HTTP traffic never reaches the public internet. All
three conditions must be true:

1. The network policy explicitly allows the destination.
2. The matched endpoint has `allowed_ips` configured.
3. All resolved IP addresses are RFC 1918 private (`10/8`, `172.16/12`, `192.168/16`).

If any condition fails, the proxy returns 403.

| Condition | Forward proxy | CONNECT |
|---|---|---|
| Public IP, no `allowed_ips` | 403 | Allowed (standard SSRF check) |
| Public IP, with `allowed_ips` | 403 (private-IP gate) | Allowed if IP in allowlist |
| Private IP, no `allowed_ips` | 403 | 403 (SSRF block) |
| Private IP, with `allowed_ips` | Allowed | Allowed |
| `https://` scheme | 403 (must use CONNECT) | N/A |

### Policy Configuration

No new policy fields are needed. The same `network_policies` entry that enables
CONNECT access to a private endpoint also enables forward proxy access. Add
`allowed_ips` to the endpoint:

```yaml
network_policies:
  internal_service:
    name: internal-service
    endpoints:
      - host: 10.86.8.223
        port: 8000
        allowed_ips:
          - "10.86.8.223/32"
    binaries:
      - path: /usr/local/bin/python3.12
```

With this policy, both CONNECT and forward proxy requests to the endpoint work:

```python
import httpx
resp = httpx.get("http://10.86.8.223:8000/api/",
                 proxy="http://10.200.0.1:3128")
```

### Limitations

- Forward proxy v1 injects `Connection: close` (no keep-alive). Each connection handles exactly one request-response exchange.
- L7 inspection is not performed on forwarded traffic.
- `https://` URLs must use the CONNECT tunnel, not the forward proxy path.

## Enforcement Modes

Each endpoint can operate in one of two enforcement modes:

| Mode      | Behavior on violation |
|-----------|-----------------------|
| `enforce` | Blocks the request and returns HTTP 403 to the calling process. The violation is logged. |
| `audit`   | Logs the violation but forwards the traffic to the destination. The agent is not interrupted. |

:::{tip}
Start with `enforcement: audit` when developing a new policy. Audit mode shows you what *would* be blocked without actually breaking the agent. After the policy is correct and you have confirmed that no legitimate traffic is flagged, switch to `enforcement: enforce`.
:::

## Putting It Together

Here is a realistic policy snippet for an agent that needs to reach its own API, clone Git repositories (read-only), and install npm packages:

```yaml
network_policies:
  agent_api:
    name: agent-api
    endpoints:
      - host: api.anthropic.com
        port: 443
        protocol: rest
        tls: terminate
        enforcement: enforce
        access: full
    binaries:
      - path: /usr/local/bin/claude
      - path: /usr/bin/node

  github:
    name: github
    endpoints:
      - host: github.com
        port: 443
        protocol: rest
        tls: terminate
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: /**/info/refs*
          - allow:
              method: POST
              path: /**/git-upload-pack
    binaries:
      - path: /usr/bin/git

  npm_registry:
    name: npm-registry
    endpoints:
      - host: registry.npmjs.org
        port: 443
    binaries:
      - path: /usr/bin/npm
      - path: /usr/bin/node
      - path: /usr/local/bin/npm
      - path: /usr/local/bin/node
```

## Next Steps

- [Write Sandbox Policies](policies.md): The full iterative workflow for authoring, testing, and updating policies.
- {doc}`security-model`: Threat scenarios and how the four protection layers work together.
