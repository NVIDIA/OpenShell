<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Policy Schema Reference

This is the complete YAML schema for NemoClaw sandbox policies. For a guide on using policies, see [Policies](../security/policies.md).

## Full Schema

```yaml
filesystem_policy:
  read_only:                    # List of paths — read-only access (Landlock)
    - /usr
    - /etc
    - /lib
  read_write:                   # List of paths — read-write access (auto-created, chowned)
    - /sandbox
    - /tmp

landlock:
  compatibility: best_effort    # best_effort | hard_requirement

process:
  run_as_user: sandbox          # Username or UID
  run_as_group: sandbox         # Group name or GID

network_policies:               # Map of named network policy entries
  <policy-name>:
    endpoints:
      - host: <hostname>        # Destination hostname
        port: <port>            # Destination port (integer)
        l7:                     # Optional — L7 inspection config
          tls_mode: terminate   # terminate
          enforcement_mode: enforce  # enforce | audit
          access: <preset>      # read-only | read-write | full (expands to rules)
          rules:                # Explicit HTTP rules (mutually exclusive with access)
            - method: <METHOD>  # HTTP method (GET, POST, PUT, DELETE, etc.)
              path_pattern: <pattern>  # URL path pattern (glob)
    binaries:
      - path_patterns:          # List of glob patterns for binary paths
          - "**/git"
          - "/usr/bin/curl"

inference:
  allowed_routes:               # List of routing hint names
    - local
    - cloud
```

## Field Reference

### `filesystem_policy`

Controls directory-level access enforced by the Linux Landlock LSM.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `read_only` | `list[string]` | No | Paths the agent can read but not write. |
| `read_write` | `list[string]` | No | Paths the agent can read and write. Directories are created and ownership is set to the `run_as_user` automatically. |

**Note:** The working directory (`--workdir`, default `/sandbox`) is automatically added to `read_write` unless `include_workdir` is set to `false`.

### `landlock`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `compatibility` | `string` | `best_effort` | `best_effort` — use the best available Landlock ABI version. `hard_requirement` — fail startup if the required ABI is not available. |

### `process`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `run_as_user` | `string` | No | Username or UID the child process runs as. |
| `run_as_group` | `string` | No | Group name or GID the child process runs as. |

### `network_policies`

A map where each key is a policy name and each value defines endpoints and allowed binaries.

#### Endpoint Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `host` | `string` | Yes | Destination hostname to match. |
| `port` | `integer` | Yes | Destination port to match. |
| `l7` | `object` | No | L7 inspection configuration (see below). |

#### L7 Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `tls_mode` | `string` | Yes | Must be `terminate` — the proxy terminates TLS and inspects plaintext HTTP. |
| `enforcement_mode` | `string` | No | `enforce` (default) — block non-matching requests. `audit` — log violations but allow traffic. |
| `access` | `string` | No | Preset: `read-only`, `read-write`, or `full`. Mutually exclusive with `rules`. |
| `rules` | `list[object]` | No | Explicit HTTP rules. Mutually exclusive with `access`. |

#### L7 Rule Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `method` | `string` | Yes | HTTP method (`GET`, `POST`, `PUT`, `DELETE`, `PATCH`, `HEAD`, `OPTIONS`). |
| `path_pattern` | `string` | Yes | URL path pattern (glob matching). |

#### Access Presets

| Preset | Expands To |
|--------|-----------|
| `read-only` | `GET`, `HEAD`, `OPTIONS` |
| `read-write` | `GET`, `HEAD`, `OPTIONS`, `POST`, `PUT`, `PATCH`, `DELETE` |
| `full` | All HTTP methods |

#### Binary Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `path_patterns` | `list[string]` | Yes | Glob patterns matched against the full path of the requesting executable. |

### `inference`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `allowed_routes` | `list[string]` | No | List of routing hint names. Routes are created via `nemoclaw inference create`. |

## Static vs. Dynamic Fields

| Category | Fields | Updatable at Runtime? |
|----------|--------|----------------------|
| **Static** | `filesystem_policy`, `landlock`, `process` | No — immutable after creation. |
| **Dynamic** | `network_policies`, `inference` | Yes — updated via `nemoclaw sandbox policy set`. |

## Example: Development Policy

```yaml
filesystem_policy:
  read_only:
    - /usr
    - /etc
    - /lib
    - /lib64
    - /bin
    - /sbin
  read_write:
    - /sandbox
    - /tmp
    - /home/sandbox

landlock:
  compatibility: best_effort

process:
  run_as_user: sandbox
  run_as_group: sandbox

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
      - path_patterns: ["**/curl"]

  anthropic:
    endpoints:
      - host: api.anthropic.com
        port: 443
    binaries:
      - path_patterns: ["**/claude"]
      - path_patterns: ["**/node"]

  pypi:
    endpoints:
      - host: pypi.org
        port: 443
      - host: files.pythonhosted.org
        port: 443
    binaries:
      - path_patterns: ["**/pip"]
      - path_patterns: ["**/python*"]

inference:
  allowed_routes:
    - local
```
