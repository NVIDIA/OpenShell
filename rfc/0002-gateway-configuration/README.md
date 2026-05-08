---
authors:
  - "@TaylorMutch"
state: review
---

# RFC 0002 - Gateway Configuration File

## Summary

Introduce a TOML-based configuration file for the OpenShell gateway that unifies all gateway settings — core server options, TLS, OIDC, observability listeners, and per-driver parameters — under a single structured file, while preserving full backwards compatibility with the existing CLI flags and `OPENSHELL_*` environment variables.

## Motivation

The gateway today is configured exclusively through CLI flags and `OPENSHELL_*` environment variables. This works for simple single-node deployments but breaks down as deployments grow:

- **Too many flags** — the gateway has ~40 configurable parameters today (TLS, OIDC, four compute drivers, three listeners). Long `docker run` commands and `args:` arrays in Kubernetes manifests are hard to read, diff, and audit.
- **Driver coupling** — Docker, Podman, Kubernetes, and VM drivers all live in the same flat CLI namespace, with no structural separation. Most flags only apply to one driver, but there is no way to express that in CLI form.
- **Helm friction** — The chart's `statefulset.yaml` already carries a long `env:` block of `OPENSHELL_*` variables that each map to a `values.yaml` key. A config file can be mounted as a single `ConfigMap` and reduces the chart's templating surface significantly.
- **Secrets management** — Injecting secrets (TLS material paths, handshake secret, database URL, OIDC settings) via environment variables is functional but not idiomatic for Kubernetes. A file-based format opens the door to projected secrets and volume mounts that compose cleanly with the non-secret config.

## Non-goals

- Sandbox workload policy (OPA rules, network rules) — sandboxes receive policy from the gateway over the control-plane API; this RFC does not change that.
- Hot-reload of configuration without restarting the gateway process.
- Support for config formats other than TOML. JSON or YAML variants are not planned.
- A new configuration schema for the CLI client (`openshell` binary) — this RFC covers the server process (`openshell-gateway`) only.
- Auto-detection logic for compute drivers. The gateway already auto-detects an active driver when none is configured (Kubernetes → Podman → Docker); the file simply provides another way to specify drivers explicitly.

## Proposal

### Configuration sources and precedence

Three sources are merged at startup, in descending priority:

```
CLI flags  >  OPENSHELL_* environment variables  >  TOML config file  >  built-in defaults
```

The TOML file is optional. If neither `--config` nor `OPENSHELL_CONFIG` is set, the gateway behaves exactly as before. Any field present in the file is overridden by a CLI flag or matching environment variable.

### Loading the file

The file path is provided via:

```
--config /path/to/gateway.toml
OPENSHELL_CONFIG=/path/to/gateway.toml
```

The file must have a `.toml` extension. A missing path is a hard error; an empty existing file is treated as "no configuration" — the gateway falls back to defaults and to whatever the CLI/env supply.

### TOML schema

The file is rooted at an `[openshell]` table. This namespacing reserves room for future components (CLI, sandbox, router) to share a single config file without key collisions.

`[openshell.gateway]` carries gateway-wide settings only. Fields that only matter to a specific compute driver live under `[openshell.drivers.<name>]` and are owned by that driver.

```toml
[openshell]
version = 1                      # optional; reserved for future schema migrations

# ──────────────────────────────────────────────────────────────────────────────
# Gateway-wide settings
# ──────────────────────────────────────────────────────────────────────────────
[openshell.gateway]
# Listener
bind_address          = "127.0.0.1:8080"   # default: 127.0.0.1:8080 (loopback)
health_bind_address   = "0.0.0.0:8081"     # optional; omit to disable
metrics_bind_address  = "0.0.0.0:9090"     # optional; omit to disable
extra_bind_addresses  = []                 # additional listeners (driver callbacks, etc.)

# Logging
log_level             = "info"

# Compute drivers — list of driver names whose [openshell.drivers.<name>]
# tables should be activated. When empty, the gateway auto-detects a driver
# (kubernetes → podman → docker). VM is never auto-detected.
compute_drivers       = ["kubernetes"]

# SSH proxy (gateway-side; driver-side equivalents live under each driver).
# Note: ssh_handshake_secret is a secret and must be supplied via
# OPENSHELL_SSH_HANDSHAKE_SECRET (or --ssh-handshake-secret) — it is NOT
# permitted in the file. database_url is the same: env / CLI only.
ssh_handshake_skew_secs = 300
ssh_session_ttl_secs    = 86400
ssh_gateway_host        = "127.0.0.1"
ssh_gateway_port        = 8080
ssh_connect_path        = "/connect/ssh"
sandbox_ssh_port        = 2222

# ──────────────────────────────────────────────────────────────────────────────
# TLS / mTLS — when omitted, the gateway listens plaintext (sets --disable-tls)
# ──────────────────────────────────────────────────────────────────────────────
[openshell.gateway.tls]
cert_path             = "/etc/openshell/certs/gateway.pem"
key_path              = "/etc/openshell/certs/gateway-key.pem"
client_ca_path        = "/etc/openshell/certs/client-ca.pem"
allow_unauthenticated = false   # mirrors --disable-gateway-auth

# ──────────────────────────────────────────────────────────────────────────────
# OIDC — when omitted, JWT bearer auth is disabled
# ──────────────────────────────────────────────────────────────────────────────
[openshell.gateway.oidc]
issuer        = "https://idp.example.com/realms/openshell"
audience      = "openshell-cli"
jwks_ttl_secs = 3600
roles_claim   = "realm_access.roles"   # Keycloak default; "roles" for Entra, "groups" for Okta
admin_role    = "openshell-admin"
user_role     = "openshell-user"
scopes_claim  = ""                     # empty disables scope enforcement

# ──────────────────────────────────────────────────────────────────────────────
# Compute drivers — each table is owned and parsed by its driver crate.
# Only tables for drivers listed in compute_drivers are activated.
# ──────────────────────────────────────────────────────────────────────────────

[openshell.drivers.kubernetes]
namespace                    = "openshell"
default_image                = "ghcr.io/nvidia/openshell/sandbox:latest"
image_pull_policy            = "IfNotPresent"
supervisor_image             = "ghcr.io/nvidia/openshell/supervisor:latest"
supervisor_image_pull_policy = "IfNotPresent"
grpc_endpoint                = "https://host.openshell.internal:8080"
client_tls_secret_name       = "openshell-sandbox-tls"
host_gateway_ip              = "10.0.0.1"
ssh_socket_path              = "/run/openshell/ssh.sock"

[openshell.drivers.docker]
network_name      = "openshell"
supervisor_bin    = "/usr/local/libexec/openshell/openshell-sandbox"  # optional override
supervisor_image  = "ghcr.io/nvidia/openshell/supervisor:latest"      # used to extract bin
guest_tls_ca      = "/etc/openshell/certs/ca.pem"
guest_tls_cert    = "/etc/openshell/certs/client.pem"
guest_tls_key     = "/etc/openshell/certs/client-key.pem"

[openshell.drivers.podman]
socket_path       = "/run/podman/podman.sock"
default_image     = "ghcr.io/nvidia/openshell/sandbox:latest"
image_pull_policy = "IfNotPresent"
supervisor_image  = "ghcr.io/nvidia/openshell/supervisor:latest"
network_name      = "openshell"
stop_timeout_secs = 10
guest_tls_ca      = "/etc/openshell/certs/ca.pem"
guest_tls_cert    = "/etc/openshell/certs/client.pem"
guest_tls_key     = "/etc/openshell/certs/client-key.pem"

[openshell.drivers.vm]
state_dir       = "/var/lib/openshell/vm"
driver_dir      = "/usr/local/libexec/openshell"
vcpus           = 2
mem_mib         = 2048
krun_log_level  = 1
guest_tls_ca    = "/var/lib/openshell/guest-tls/ca.pem"
guest_tls_cert  = "/var/lib/openshell/guest-tls/client.pem"
guest_tls_key   = "/var/lib/openshell/guest-tls/client-key.pem"
```

### Driver configuration

Each `[openshell.drivers.<name>]` table is extracted from the parsed file and handed to the driver's initialization function as a raw TOML value. The driver is then responsible for:

1. **Parsing** — deserializing the table into its own typed config struct (e.g. `KubernetesComputeConfig`, `DockerComputeConfig`, `PodmanComputeConfig`, `VmComputeConfig`).
2. **Validation** — applying cross-field checks specific to that driver (e.g. requiring TLS triplets when sandbox-side mTLS is enabled).
3. **Consumption** — using the resulting struct to initialize internal state.

Driver authors define and own their config schema. Adding a new driver does not require changes to the gateway's core `Config` struct or to this RFC.

`[openshell.drivers.<name>]` tables for drivers not listed in `compute_drivers` (and not the auto-detected driver) are parsed for syntax but not activated.

### Merge semantics

Field-level merge rules:

1. **`[openshell.gateway]`** populates `openshell_core::Config` (including the nested `[openshell.gateway.tls]` and `[openshell.gateway.oidc]` tables, which map to `TlsConfig` and `OidcConfig` respectively).
2. **`[openshell.drivers.<name>]`** is propagated to the driver crate, which deserializes it into its own struct. Driver schemas evolve independently of the gateway's core `Config`.
3. **CLI / env** override any value set by steps 1–2, field by field. The override check uses clap's `ValueSource` — a value is applied from the file only when the corresponding flag was not supplied via the command line or environment.

`bind_address`, `health_bind_address`, and `metrics_bind_address` are stored as `SocketAddr` (IP + port). The CLI exposes them as a single `--bind-address` IP plus `--port`, `--health-port`, and `--metrics-port`; CLI overrides apply to the matching part of the parsed `SocketAddr`.

`health_bind_address` and `metrics_bind_address` may be omitted to disable those listeners (matching the current behavior of `--health-port 0` / `--metrics-port 0`).

### Secrets

Two fields are deliberately excluded from the TOML schema and must be supplied via environment variable or CLI flag:

| Field | Source |
|---|---|
| `database_url` | `OPENSHELL_DB_URL` / `--db-url` |
| `ssh_handshake_secret` | `OPENSHELL_SSH_HANDSHAKE_SECRET` / `--ssh-handshake-secret` |

These two values are high-value secrets where a leaked plaintext file is materially worse than a leaked env var (database URLs typically embed credentials; the handshake secret authenticates every gateway↔sandbox SSH session). Forcing them out of the file removes the easiest accidental-commit path.

If either field appears under `[openshell.gateway]`, the parser fails with a clear error pointing operators at the env/CLI form.

OIDC settings (including `oidc.audience`, `oidc.admin_role`, etc.) **are** allowed in the file. None of them are credentials by themselves. However, operators should still prefer env-var injection for any field they would otherwise store in a Kubernetes `Secret` — TLS material paths, OIDC issuer URLs in restricted environments, and so on. The general guidance: if it would live in a `Secret` resource, source it from an env var; if it would live in a `ConfigMap`, the file is fine.

### Validation

Deserialization uses `#[serde(deny_unknown_fields)]` at every table level. An unrecognised key is a hard parse error. This catches typos early rather than silently ignoring misconfigured fields.

The following cross-field validations are applied after merging file + env + CLI:

- `bind_address`, `health_bind_address`, and `metrics_bind_address` must all use distinct ports when set.
- When `[openshell.gateway.tls]` is present, all three of `cert_path`, `key_path`, and `client_ca_path` must be present (either from the file or from CLI/env). Partial TLS configuration is an error.
- `database_url` must be non-empty after merging env + CLI — every supported driver requires it. The field is not accepted from the file (see Secrets above).
- `ssh_handshake_secret` is not accepted from the file. Drivers that require it surface a runtime error if env/CLI did not provide it.
- `compute_drivers` may be empty; in that case the gateway falls back to auto-detection. If the list contains a driver name with no matching `[openshell.drivers.<name>]` table, the driver runs with its built-in defaults.

### Backwards compatibility

The existing CLI interface is fully preserved. All flags continue to work exactly as before. The `--config` flag is new and additive. `OPENSHELL_DB_URL` and `OPENSHELL_SSH_HANDSHAKE_SECRET` remain required process inputs (they are not accepted from the file).

### Example: minimal Kubernetes deployment

```toml
[openshell]
version = 1

[openshell.gateway]
bind_address    = "0.0.0.0:8080"
compute_drivers = ["kubernetes"]
# database_url and ssh_handshake_secret come from env (e.g. valueFrom.secretKeyRef).
# No [openshell.gateway.tls] → plaintext listener (gateway runs behind Envoy / ingress).

[openshell.drivers.kubernetes]
namespace        = "agents"
default_image    = "ghcr.io/nvidia/openshell/sandbox:0.9.0"
supervisor_image = "ghcr.io/nvidia/openshell/supervisor:0.9.0"
grpc_endpoint    = "https://openshell-gateway.agents.svc:8080"
```

### Helm integration

The Helm chart today renders a long `env:` block in `templates/statefulset.yaml`, with each `OPENSHELL_*` variable mapped to a `values.yaml` key. This RFC's adoption replaces that block with:

1. A new `gateway.config` value tree (TOML-shaped YAML) in `values.yaml`.
2. A new `ConfigMap` template that renders the values into a TOML document via Helm's `tpl`.
3. A volume mount of the `ConfigMap` at `/etc/openshell/gateway.toml` and a `--config` flag in the gateway container's `args`.
4. Continued use of `Secret`-backed `env:` entries for `OPENSHELL_DB_URL` and `OPENSHELL_SSH_HANDSHAKE_SECRET` (these never live in the `ConfigMap`), plus optional projections for TLS material paths. The CLI/env precedence above means any `Secret`-backed env var also wins over a value in the `ConfigMap`.

```yaml
# values.yaml excerpt
gateway:
  config:
    bind_address: "0.0.0.0:8080"
    health_bind_address: "0.0.0.0:8081"
    metrics_bind_address: "0.0.0.0:9090"
    compute_drivers: ["kubernetes"]
    drivers:
      kubernetes:
        namespace: agents
        default_image: ghcr.io/nvidia/openshell/sandbox:0.9.0
        supervisor_image: ghcr.io/nvidia/openshell/supervisor:0.9.0
```

The chart owners can migrate one section at a time: `OPENSHELL_*` env vars and the `ConfigMap` coexist during the transition, with env continuing to override the file.

## Implementation plan

No part of this RFC has shipped yet. The work breaks down as:

1. **Add a config-file loader to `openshell-server`** — define a `GatewayConfigFile` struct that mirrors the schema above, parse it with `serde` + `toml`, and merge it into `openshell_core::Config` plus the per-driver structs in `compute/`.
2. **Wire the merge into `cli.rs`** — add `--config` / `OPENSHELL_CONFIG`, gate each existing flag's "apply from file" path on clap `ValueSource::DefaultValue`, and run cross-field validation after the merge.
3. **Per-driver deserialization** — give each driver crate (`openshell-driver-{kubernetes,docker,podman,vm}`) a `from_toml` (or `serde::Deserialize`) entry point so the gateway can hand each driver its own table.
4. **Test coverage** — file parsing, env-overrides-file, CLI-overrides-env, partial TLS error, port-collision error, unknown-field rejection, missing driver table fallback.
5. **Helm chart migration** — add `gateway.config` value tree, render the `ConfigMap`, mount it, switch the gateway container to `--config`. Keep the `OPENSHELL_*` env names available as opt-in overrides for secrets.
6. **Example file** — ship `examples/gateway/gateway.example.toml` and link it from the docs reference.
7. **Architecture doc update** — reflect the new config sources and precedence in `architecture/gateway.md`.

## Risks

- **Serde `deny_unknown_fields` is strict** — any field name change in `openshell_core::Config` or in a driver's config struct becomes a breaking change for anyone using the file. Mitigate by treating field renames as breaking, keeping the `version` field reserved for schema migrations, and surfacing rename errors clearly.
- **Secrets in the file** — `database_url` and `ssh_handshake_secret` are excluded from the schema entirely (env / CLI only). OIDC settings remain allowed in the file because none of them are credentials in isolation. Operators should still prefer env-var injection for any field that would live in a `Secret` rather than a `ConfigMap` (TLS material paths, restricted-environment OIDC issuers, etc.). Documentation must call this out prominently.
- **Partial TLS configuration** — the hard error on partial TLS config is the right UX, but the error message must clearly identify which source (file vs. CLI/env) is missing which field, since the file's `[openshell.gateway.tls]` table is all-or-nothing while the CLI flags are independent.
- **Driver schema drift** — once each driver owns its own TOML table, driver releases can change field names independently of the gateway. The gateway's `version` field does not protect against driver-side breakage; document driver-config stability separately.

## Alternatives

**Flat environment variables only** — the status quo. Avoids a new file format and parsing layer, but doesn't address the driver namespacing problem and makes the Helm chart verbose. Rejected: the long-term Kubernetes story requires a file-based approach.

**YAML instead of TOML** — YAML is already the dominant format in the Kubernetes ecosystem, and Helm values are YAML. Using YAML for the gateway config would align with that ecosystem. The downside is YAML's well-known footguns (Norway problem, implicit typing, indentation sensitivity). TOML is unambiguous and maps cleanly to Rust structs via `serde`. For a config file primarily edited by humans, TOML's clarity wins. The Helm chart can still generate a TOML file from YAML values via `tpl`.

**Separate config crate** — centralising config parsing in a dedicated `openshell-config` crate rather than inside `openshell-server`. Worthwhile if other binaries need the same config format; deferred until there is a concrete need.

## Prior art

- [Gitea](https://docs.gitea.com/administration/config-cheat-sheet) and [InfluxDB](https://docs.influxdata.com/influxdb/v2/reference/config-options/) both use TOML for their primary server configuration with environment variable and CLI flag overrides following the same precedence order proposed here.
- The `[tool.*]` namespace convention in `pyproject.toml` inspired the `[openshell.*]` root table — a single file can host configuration for multiple tools without key collisions.
- Rust's own `config.toml` (`~/.cargo/config.toml`) follows similar principles: file provides defaults, environment overrides, explicit flags override environment.

## Open questions

1. **Schema versioning** — the `version` field is reserved but not acted on. Should the parser reject files with `version > 1`, or just warn? Define this before the first stable release.
2. **Directory-based config (`conf.d` pattern)** — a `--config-dir` flag that globs all `*.toml` files in a directory, sorts them alphabetically, and deep-merges them in order (later files win per key). CLI/env overrides still sit above everything. This maps cleanly to Kubernetes: a base `ConfigMap` as `10-base.toml`, driver config as `20-kubernetes.toml`, and credentials from a projected `Secret` as `90-credentials.toml` — all mounted into the same directory without a monolithic file. This is the approach taken by cri-o and kubelet, inspired by systemd's `conf.d` convention.

   Deferred to a follow-on: the single `--config` file is sufficient for v1, and the directory loader can be added without any schema changes. Before implementing, three design decisions must be settled: (a) whether `--config` and `--config-dir` are mutually exclusive or composable (and if so which takes lower precedence); (b) whether a later file's array value (e.g. `compute_drivers`) replaces or appends — replace is simpler and less surprising; (c) `deny_unknown_fields` validation must apply to the final merged result rather than each individual file, since partial drop-in files won't contain all sections.
3. **OIDC secret hygiene (revisit)** — `database_url` and `ssh_handshake_secret` are excluded from the file schema (resolved). OIDC settings are allowed for v1 since the listed fields are identifiers, not credentials. If we add OIDC fields that *are* credentials in the future (e.g. a client secret for confidential-client flows), they should join the env-only list at that point. Re-evaluate once the OIDC surface stabilises.
