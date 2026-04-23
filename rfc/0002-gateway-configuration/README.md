---
authors:
  - "@TaylorMutch"
state: review
---

# RFC 0002 - Gateway Configuration File

## Summary

Introduce a TOML-based configuration file for the OpenShell gateway that unifies all gateway settings — core server options, TLS, and compute driver parameters — under a single structured file, while preserving full backwards compatibility with the existing CLI flags and environment variables.

## Motivation

The gateway today is configured exclusively through CLI flags and `OPENSHELL_*` environment variables. This works for simple single-node deployments but breaks down as deployments grow:

- **Too many flags** — the gateway has 20+ configurable parameters. Long `docker run` commands and `args:` arrays in Kubernetes manifests are hard to read, diff, and audit.
- **Driver coupling** — Kubernetes-driver settings and VM-driver settings live in the same flat CLI namespace, with no structural separation. Adding new drivers or per-driver overrides requires more flags.
- **Helm friction** — The Helm chart has to manage a long `env:` block of `OPENSHELL_*` variables and map each one to a `values.yaml` key. A config file can be mounted as a single `ConfigMap` and reduces the chart's templating surface significantly. (See [RFC 0003](../0003-helm/README.md) for the Helm release plan.)
- **Secrets management** — Injecting secrets (TLS paths, handshake secrets, database credentials) via environment variables is functional but not idiomatic for Kubernetes. A file-based format opens the door to projected secrets and volume mounts.

## Non-goals

- Sandbox workload policy (OPA rules, network rules) — sandboxes receive policy from the gateway over the control-plane API; this RFC does not change that.
- Hot-reload of configuration without restarting the gateway process.
- Support for config formats other than TOML. JSON or YAML variants are not planned.
- A new configuration schema for the CLI client (`openshell` binary) — this RFC covers the server process (`openshell-gateway`) only.

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

The file must have a `.toml` extension. An empty or missing file is treated as "no configuration" — the gateway falls back to defaults.

### TOML schema

The file is rooted at an `[openshell]` table. This namespacing reserves room for future components to share a single config file without key collisions.

```toml
[openshell]
version = 1               # optional; reserved for future schema migrations

[openshell.gateway]
# Core gateway settings
database_url              = "postgres://localhost/openshell"
bind_address              = "0.0.0.0:8080"
port                      = 8080         # shorthand for bind_address (all interfaces)
health_port               = 9090         # 0 = disable dedicated health listener
log_level                 = "info"
compute_drivers           = ["kubernetes"]

# TLS
disable_tls               = false
disable_gateway_auth      = false        # allow connections without client cert
[openshell.gateway.tls]
cert_path                 = "/etc/openshell/certs/gateway.pem"
key_path                  = "/etc/openshell/certs/gateway-key.pem"
client_ca_path            = "/etc/openshell/certs/client-ca.pem"
allow_unauthenticated     = false

# SSH handshake / proxy
ssh_handshake_secret      = "CHANGE_ME"
ssh_handshake_skew_secs   = 300
ssh_session_ttl_secs      = 86400
ssh_gateway_host          = "127.0.0.1"
ssh_gateway_port          = 8080
ssh_connect_path          = "/connect/ssh"

# Kubernetes fields (can also live under [openshell.drivers.kubernetes])
sandbox_namespace         = "default"
sandbox_image             = "ghcr.io/nvidia/openshell-sandbox:latest"
sandbox_image_pull_policy = "IfNotPresent"
grpc_endpoint             = "https://host.openshell.internal:8080"
client_tls_secret_name    = "openshell-sandbox-tls"
host_gateway_ip           = "10.0.0.1"
sandbox_ssh_socket_path   = "/run/openshell/ssh.sock"

# Driver-specific configuration — propagated to each driver at startup.
# Each driver parses, validates, and consumes its own section independently.
[openshell.drivers.kubernetes]
sandbox_namespace         = "production"
grpc_endpoint             = "https://gw.internal:8080"

[openshell.drivers.vm]
state_dir                 = "/var/lib/openshell/vm"
vcpus                     = 2
mem_mib                   = 2048
krun_log_level            = 1
driver_dir                = "/usr/local/libexec/openshell"
guest_tls_ca              = "/var/lib/openshell/guest-tls/ca.pem"
guest_tls_cert            = "/var/lib/openshell/guest-tls/client.pem"
guest_tls_key             = "/var/lib/openshell/guest-tls/client-key.pem"
```

### Driver configuration

The `[openshell.drivers.<name>]` table for each active driver is extracted from the parsed file and passed to the driver's initialization function. The driver is then responsible for:

1. **Parsing** — deserializing the raw TOML table into its own config struct (e.g., `KubernetesDriverConfig`, `VmDriverConfig`).
2. **Validation** — applying cross-field checks specific to that driver (e.g., ensuring required fields are present when a particular feature is enabled).
3. **Consumption** — using the resulting config struct to initialize its internal state and resources.

This means driver authors define and own their config schema. Adding a new driver does not require changes to the gateway's core `Config` struct.

### Merge semantics

Field-level merge rules:

1. **`[openshell.gateway]`** populates the `Config` struct. This is the base layer from the file.
2. **`[openshell.drivers.<name>]`** sections are propagated to their respective compute drivers at startup. Each driver receives its own TOML table, deserializes it into its own typed config struct, and performs its own validation. This decouples driver configuration from the global `Config` struct — drivers can evolve their config schema independently without touching the core config type. Drivers not listed in `compute_drivers` have their sections ignored.
3. **CLI / env** override any value set by steps 1–2, field by field. The override check uses clap's `ValueSource` — a value is applied from the file only when the corresponding flag was not supplied via the command line or environment.

The `port` and `health_port` shorthand fields in `[openshell.gateway]` set `bind_address` and `health_bind_address` respectively, expanding to `0.0.0.0:<port>`.

`health_port = 0` disables the dedicated health listener.

### Validation

Deserialization uses `#[serde(deny_unknown_fields)]` at every table level. An unrecognised key is a hard parse error. This catches typos early rather than silently ignoring misconfigured fields.

The following cross-field validations are applied after parsing:

- `health_bind_address` must differ from `bind_address` when both are set.
- When TLS is enabled (i.e., `disable_tls = false`), all three of `cert_path`, `key_path`, and `client_ca_path` must be present — either from the file or from CLI/env. Partial TLS configuration is an error.
- `database_url` can be empty only when no driver requires it. Currently the Kubernetes driver requires it, so a missing `database_url` produces a runtime error rather than a parse error.

### Backwards compatibility

The existing CLI interface is fully preserved. All flags continue to work exactly as before. The `--config` flag is new and additive. The `OPENSHELL_DB_URL` environment variable is no longer required on the CLI (it can now come from the file), but it still works when set.

### Example: minimal Kubernetes deployment

```toml
[openshell]
version = 1

[openshell.gateway]
database_url    = "postgres://pghost/openshell"
ssh_handshake_secret = "replace-with-random-secret"
disable_tls     = true
compute_drivers = ["kubernetes"]

[openshell.drivers.kubernetes]
sandbox_namespace = "agents"
sandbox_image     = "ghcr.io/nvidia/openshell-sandbox:0.9.0"
grpc_endpoint     = "https://openshell-gateway.agents.svc:8080"
```

### Helm integration

In a Helm chart deployment, the config file is rendered from a `ConfigMap` using a Helm `tpl` call over the values. Operators configure the gateway by editing `values.yaml` rather than managing a long `env:` block. Secrets (TLS paths, handshake secret, database URL) are injected via projected volumes or environment variable overrides that take precedence over the file. See [RFC 0003](../0003-helm/README.md) for the full Helm release plan.

```yaml
# values.yaml excerpt
gateway:
  config:
    database_url: "postgres://pghost/openshell"
    disable_tls: true
    drivers:
      kubernetes:
        sandbox_namespace: agents
        sandbox_image: ghcr.io/nvidia/openshell-sandbox:0.9.0
```

The chart renders this into a `ConfigMap` mounted at `/etc/openshell/gateway.toml` and passes `--config /etc/openshell/gateway.toml` to the gateway container.

## Implementation plan

The implementation is already prototyped on the `scratch/server-config-file` branch. The remaining work to reach merge-ready state:

1. **Review and clean up `gateway_config_file.rs`** — the merge logic and TOML schema are implemented; polish error messages and add inline documentation.
2. **Extend test coverage** — add tests for TLS merge paths, partial-TLS error, health-port collision, and unknown-field rejection.
3. **Update the Helm chart** — add `gateway.config` value tree and the `ConfigMap` template. Connect `--config` to the gateway `Deployment` args.
4. **Ship the example file** — `examples/gateway/gateway.example.toml` is already present; verify it is included in the docs site reference.
5. **Update architecture docs** — reflect the new config sources and precedence in `architecture/gateway.md`.

## Risks

- **Serde `deny_unknown_fields` is strict** — any field name change in `openshell_core::Config` is now a breaking change for anyone using the file. Mitigate by keeping field names stable and versioning the schema (`version` field is reserved for this purpose).
- **Secrets in the file** — `ssh_handshake_secret` and `database_url` may appear in the TOML file in plaintext. Operators should treat the file as a secret and use appropriate file permissions or Kubernetes `Secret` objects for sensitive values rather than `ConfigMap`. This should be called out prominently in documentation.
- **Partial TLS configuration** — the hard error on partial TLS config is the right UX, but the error message must be clear about which source (file vs CLI) is missing which field.

## Alternatives

**Flat environment variables only** — the status quo. Avoids a new file format and parsing layer, but doesn't address the driver namespacing problem and makes Helm charts verbose. Rejected: the long-term Helm/Kubernetes story requires a file-based approach.

**YAML instead of TOML** — YAML is already the dominant format in the Kubernetes ecosystem, and Helm values are YAML. Using YAML for the gateway config file would align with that ecosystem. The downside is YAML's well-known footguns (Norway problem, implicit typing, indentation sensitivity). TOML is unambiguous and maps cleanly to Rust structs via `serde`. For a config file that is primarily edited by humans, TOML's clarity wins. The Helm chart can still generate a TOML file from YAML values.

**Separate config crate** — centralising config parsing in a dedicated `openshell-config` crate rather than inside `openshell-server`. Worthwhile if other binaries need the same config format; deferred until there is a concrete need.

## Prior art

- [Gitea](https://docs.gitea.com/administration/config-cheat-sheet) and [InfluxDB](https://docs.influxdata.com/influxdb/v2/reference/config-options/) both use TOML for their primary server configuration with environment variable and CLI flag overrides following the same precedence order proposed here.
- The `[tool.*]` namespace convention in `pyproject.toml` inspired the `[openshell.*]` root table — a single file can host configuration for multiple tools without key collisions.
- Rust's own `config.toml` (`~/.cargo/config.toml`) follows similar principles: file provides defaults, environment overrides, explicit flags override environment.

## Open questions

1. **Schema versioning** — the `version` field is reserved but not acted on. Should the parser reject files with `version > 1`, or just warn? Define this before the first stable release.
2. **Multiple config files / layering** — should the gateway support a system-level config at `/etc/openshell/gateway.toml` and a user-level override? Probably not needed initially, but worth deciding before the format is widely adopted.
3. **`database_url` as a secret** — should `database_url` be excluded from the TOML file schema and forced through environment / secrets injection to prevent accidental plaintext commits? Or is the operator's responsibility sufficient?
