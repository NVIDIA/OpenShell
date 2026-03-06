<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Policy Schema Reference

Complete field reference for the sandbox policy YAML. Each field is documented with its type, whether it is required, and whether it is static (locked at sandbox creation) or dynamic (hot-reloadable on a running sandbox).

## Top-Level Structure

```yaml
version: 1
filesystem_policy: { ... }
landlock: { ... }
process: { ... }
network_policies: { ... }
inference: { ... }
```

| Field | Type | Required | Category | Description |
|---|---|---|---|---|
| `version` | integer | Yes | -- | Policy schema version. Must be `1`. |
| `filesystem_policy` | object | No | Static | Controls which directories the agent can read and write. |
| `landlock` | object | No | Static | Configures Landlock LSM enforcement behavior. |
| `process` | object | No | Static | Sets the user and group the agent process runs as. |
| `network_policies` | map | No | Dynamic | Declares which binaries can reach which network endpoints. |
| `inference` | object | No | Dynamic | Controls which inference routing backends are available. |

Static fields are set at sandbox creation time. Changing them requires destroying and recreating the sandbox. Dynamic fields can be updated on a running sandbox with `nemoclaw sandbox policy set` and take effect without restarting.

## Version

| Field | Type | Required | Description |
|---|---|---|---|
| `version` | integer | Yes | Schema version number. Currently must be `1`. |

## Filesystem Policy

**Category:** Static

Controls filesystem access inside the sandbox. Paths not listed in either `read_only` or `read_write` are inaccessible.

| Field | Type | Required | Description |
|---|---|---|---|
| `include_workdir` | bool | No | When `true`, automatically adds the agent's working directory to `read_write`. |
| `read_only` | list of strings | No | Paths the agent can read but not modify. Typically system directories like `/usr`, `/lib`, `/etc`. |
| `read_write` | list of strings | No | Paths the agent can read and write. Typically `/sandbox` (working directory) and `/tmp`. |

**Validation constraints:**

- Every path must be absolute (start with `/`).
- Paths must not contain `..` traversal components. The server normalizes paths before storage, but rejects policies where traversal would escape the intended scope.
- Read-write paths must not be overly broad (for example, `/` alone is rejected).
- Each individual path must not exceed 4096 characters.
- The combined total of `read_only` and `read_write` paths must not exceed 256.

Policies that violate these constraints are rejected with `INVALID_ARGUMENT` at creation or update time. Disk-loaded YAML policies that fail validation fall back to a restrictive default.

Example:

```yaml
filesystem_policy:
  include_workdir: true
  read_only:
    - /usr
    - /lib
    - /proc
    - /dev/urandom
    - /etc
  read_write:
    - /sandbox
    - /tmp
    - /dev/null
```

## Landlock

**Category:** Static

Configures [Landlock LSM](https://docs.kernel.org/security/landlock.html) enforcement at the kernel level. Landlock provides mandatory filesystem access control below what UNIX permissions allow.

| Field | Type | Required | Values | Description |
|---|---|---|---|---|
| `compatibility` | string | No | `best_effort`, `hard_requirement` | How NemoClaw handles kernel ABI differences. `best_effort` uses the highest Landlock ABI the host kernel supports. `hard_requirement` fails if the required ABI is unavailable. |

Example:

```yaml
landlock:
  compatibility: best_effort
```

## Process

**Category:** Static

Sets the OS-level identity for the agent process inside the sandbox.

| Field | Type | Required | Description |
|---|---|---|---|
| `run_as_user` | string | No | The user name or UID the agent process runs as. Default: `sandbox`. |
| `run_as_group` | string | No | The group name or GID the agent process runs as. Default: `sandbox`. |

**Validation constraint:** Neither `run_as_user` nor `run_as_group` may be set to `root` or `0`. Policies that request root process identity are rejected at creation or update time.

Example:

```yaml
process:
  run_as_user: sandbox
  run_as_group: sandbox
```

## Network Policies

**Category:** Dynamic

A map of named network policy entries. Each entry declares a set of endpoints and a set of binaries. Only the listed binaries are permitted to connect to the listed endpoints. The map key is a logical identifier. The `name` field inside the entry is the display name used in logs.

### Network Policy Entry

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | No | Display name for the policy entry. Used in log output. Defaults to the map key. |
| `endpoints` | list of endpoint objects | Yes | Hosts and ports this entry permits. |
| `binaries` | list of binary objects | Yes | Executables allowed to connect to these endpoints. |

### Endpoint Object

Each endpoint defines a reachable destination and optional inspection rules.

| Field | Type | Required | Description |
|---|---|---|---|
| `host` | string | Yes | Hostname or IP address. Supports wildcards: `*.example.com` matches any subdomain. |
| `port` | integer | Yes | TCP port number. |
| `protocol` | string | No | Set to `rest` to enable L7 (HTTP) inspection. Omit for L4-only (TCP passthrough). |
| `tls` | string | No | TLS handling mode. `terminate` decrypts TLS at the proxy for inspection. `passthrough` forwards encrypted traffic without inspection. Only relevant when `protocol` is `rest`. |
| `enforcement` | string | No | `enforce` actively blocks disallowed requests. `audit` logs violations but allows traffic through. |
| `access` | string | No | HTTP access level. One of `read-only`, `read-write`, or `full`. Refer to table below. Mutually exclusive with `rules`. |
| `rules` | list of rule objects | No | Fine-grained per-method, per-path allow rules. Mutually exclusive with `access`. |

#### Access Levels

| Value | Allowed HTTP Methods |
|---|---|
| `full` | All methods and paths. |
| `read-only` | `GET`, `HEAD`, `OPTIONS`. |
| `read-write` | `GET`, `HEAD`, `OPTIONS`, `POST`, `PUT`, `PATCH`. |

#### Rule Object

Used when `access` is not set. Each rule explicitly allows a method and path combination.

| Field | Type | Required | Description |
|---|---|---|---|
| `allow.method` | string | Yes | HTTP method to allow (for example, `GET`, `POST`). |
| `allow.path` | string | Yes | URL path pattern. Supports `*` and `**` glob syntax. |

Example with rules:

```yaml
rules:
  - allow:
      method: GET
      path: /**/info/refs*
  - allow:
      method: POST
      path: /**/git-upload-pack
```

### Binary Object

Identifies an executable that is permitted to use the associated endpoints.

| Field | Type | Required | Description |
|---|---|---|---|
| `path` | string | Yes | Filesystem path to the executable. Supports glob patterns with `*` and `**`. For example, `/sandbox/.vscode-server/**` matches any executable under that directory tree. |

### Full Example

```yaml
network_policies:
  github_rest_api:
    name: github-rest-api
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        tls: terminate
        enforcement: enforce
        access: read-only
    binaries:
      - path: /usr/local/bin/claude
      - path: /usr/bin/node
      - path: /usr/bin/gh
  npm_registry:
    name: npm-registry
    endpoints:
      - host: registry.npmjs.org
        port: 443
    binaries:
      - path: /usr/bin/npm
      - path: /usr/bin/node
```

## Inference

**Category:** Dynamic

Controls which inference routing backends userland code can access. The `allowed_routes` list names route types that the privacy router will accept. Traffic matching an inference API pattern that targets a route type not in this list is denied.

| Field | Type | Required | Description |
|---|---|---|---|
| `allowed_routes` | list of strings | No | Routing hint labels (e.g., `local`, `nvidia`, `staging`) that this sandbox can use. Must match the `routing_hint` of inference routes created with `nemoclaw inference create`. |

Example:

```yaml
inference:
  allowed_routes:
    - local
    - nvidia
```
