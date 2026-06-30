---
authors:
  - "@elezar"
state: draft
links:
  - https://github.com/NVIDIA/OpenShell/pull/1703
---

# RFC 0005 - Named Compute Driver Registry

<!--
See rfc/README.md for the full RFC process and state definitions.
-->

## Summary

Introduce a named compute-driver registry for the OpenShell gateway. Instead of
requiring exactly one active compute driver, the gateway can initialize multiple
driver instances, give each instance a stable operator-chosen ID, and route each
sandbox to the driver selected in `SandboxSpec.compute_driver` or to a configured
default.

The first concrete use case is multiple Docker driver instances attached to
different Docker endpoints. A single gateway should be able to manage sandboxes
on more than one Docker backend while preserving explicit placement, stable
stop/delete routing, and per-driver configuration boundaries. The registry also
provides the natural home for operator-managed extension drivers connected over
the `compute_driver.proto` socket model proposed in PR #1703.

## Motivation

OpenShell currently accepts a list-shaped `compute_drivers` configuration field,
but the gateway rejects more than one configured driver at startup. The code and
documentation already describe this as a future-proofed shape for multi-backend
routing, but the runtime still has a single `ComputeRuntime`, a single resolved
driver kind, and one set of watch/reconcile loops.

That single-driver model forces operators to run separate gateways when they
want to target more than one compute backend. This is especially limiting for
Docker-based deployments. An operator may have several Docker hosts available
for agent workloads and want one gateway identity, one policy/control plane, and
one CLI registration while still creating sandboxes on a specific machine.

The gateway also needs a more general naming model before out-of-tree drivers
can become a first-class deployment shape. PR #1703 adds a socket flag for one
operator-managed compute driver, but deliberately defers name-keyed registry
semantics. Without a registry, external driver sockets, duplicate Docker
instances, and mixed built-in drivers all require separate special cases.

Leaving the current design unchanged keeps placement outside the OpenShell API.
Operators can work around the limitation with multiple gateways, but users then
choose a gateway rather than a compute target, and persisted sandbox records do
not carry the routing decision that stop, delete, watch, and reconciliation need
to remain correct over time.

## Non-goals

- Automatic scheduling, load balancing, capacity-aware placement, or fallback
  across drivers. Placement is explicit with a configured default.
- Hot-reloading the driver registry after gateway startup.
- A public driver discovery or health API in the first implementation.
- Multi-value `--drivers` activation from the CLI. This remains a possible
  follow-up.
- Migrating an existing sandbox from one driver to another.
- Changing `compute_driver.proto` to include gateway registry IDs.
- Making `template.driver_config` portable across drivers. Host-specific
  values remain driver-instance-specific. Portable mounts, devices, or other
  resources should be modeled as explicit portable API fields in separate RFCs.
- Fully specifying remote Docker daemon callback behavior in this RFC. The
  registry must not prevent remote Docker support, but callback routing for
  remote daemons needs separate validation.
- Requiring full support for multiple active Kubernetes driver instances in the
  first implementation. This RFC defines the security invariant such support
  must satisfy.

## Proposal

### Driver IDs and Kinds

Every active compute driver instance has a stable driver ID. Driver IDs are
operator-facing names used in gateway configuration, sandbox specs, logs, and
CLI arguments.

Driver IDs must be DNS-label-like ASCII strings:

```text
[a-z0-9]([-a-z0-9]*[a-z0-9])?
```

The maximum length is 63 bytes. Examples of valid IDs are `docker`, `local`,
`lab-a`, `gpu-01`, and `prod-k8s`.

Each driver ID resolves to a driver kind. Initial registry kinds are:

| Kind | Meaning |
|---|---|
| `docker` | In-tree Docker compute driver. |
| `podman` | In-tree Podman compute driver. |
| `kubernetes` | In-tree Kubernetes compute driver. |
| `vm` | In-tree VM compute driver. |
| `extension` | Operator-managed compute driver speaking `compute_driver.proto`. |

The built-in legacy IDs `docker`, `podman`, `kubernetes`, and `vm` infer their
kind when the driver table omits `kind`. All custom IDs must set `kind`
explicitly.

```toml
[openshell.gateway]
compute_drivers = ["docker"]

[openshell.drivers.docker]
# kind = "docker" is inferred for this legacy ID.
network_name = "openshell"
```

```toml
[openshell.gateway]
compute_drivers = ["local", "lab-a"]
default_compute_driver = "local"

[openshell.drivers.local]
kind = "docker"

[openshell.drivers.lab-a]
kind = "docker"
```

The `extension` name is intentional. `external` and `remote` are ambiguous once
Docker can point at remote machines. `plugin` implies discovery and lifecycle
management that this RFC does not propose. An extension driver is simply an
operator-managed implementation of the compute-driver protocol.

### Activation and Defaults

`[openshell.gateway].compute_drivers` lists active driver IDs. It no longer
means "list of driver kinds", although legacy IDs preserve existing single
driver configuration.

If `compute_drivers` is empty or unset, the gateway preserves current
auto-detection behavior: it auto-detects exactly one legacy built-in driver in
the existing order `kubernetes`, then `podman`, then `docker`. VM and extension
drivers are never auto-detected.

If exactly one driver is active, the default compute driver is inferred as that
ID. If multiple drivers are active, `default_compute_driver` is required and must
name one active driver.

```toml
[openshell.gateway]
compute_drivers = ["local", "lab-a"]
default_compute_driver = "local"
```

The default can be overridden by CLI or environment:

```shell
openshell-gateway --default-compute-driver lab-a
OPENSHELL_DEFAULT_COMPUTE_DRIVER=lab-a
```

The override follows the gateway configuration precedence from RFC 0003:

```text
CLI flag > OPENSHELL_* environment variable > TOML config file > built-in default
```

The existing `--drivers` flag remains a single-driver activation override in
this RFC. It selects one driver ID, not fundamentally a kind. When that ID is a
legacy built-in name, the driver can be inferred without a table. When it is a
custom ID, the corresponding `[openshell.drivers.<id>]` table must exist.

```shell
openshell-gateway --drivers docker
```

activates only the legacy `docker` driver ID. With a config file containing a
named extension driver:

```toml
[openshell.gateway]
compute_drivers = ["docker", "kyma"]
default_compute_driver = "docker"

[openshell.drivers.kyma]
kind = "extension"

[openshell.drivers.kyma.endpoint]
socket = "/run/openshell/kyma.sock"
```

this command activates only the `kyma` driver and makes it the effective
default:

```shell
openshell-gateway --drivers kyma
```

Multiple values in `--drivers` remain unsupported for now, even if the parser
currently accepts a comma-delimited list. Supporting multi-ID CLI activation is
a follow-up that should also require an explicit default.

### Driver Tables

Each `[openshell.drivers.<id>]` table is a complete driver instance
configuration. Multiple entries can share the same kind, and different kinds can
be mixed in the same gateway.

```toml
[openshell.gateway]
compute_drivers = ["local", "lab-a", "prod-k8s"]
default_compute_driver = "local"

[openshell.drivers.local]
kind = "docker"
sandbox_namespace = "local"

[openshell.drivers.lab-a]
kind = "docker"
sandbox_namespace = "lab-a"

[openshell.drivers.prod-k8s]
kind = "kubernetes"
namespace = "openshell-prod"
```

Inactive driver tables are parsed as TOML but are not deserialized or validated
by the target driver. This preserves RFC 0003 behavior and allows operators to
stage future driver entries in the file.

`default_compute_driver` must name an active driver. It cannot point to an
inactive table.

### Shared Defaults and Inheritance

RFC 0003 defines shared driver defaults under `[openshell.gateway]` that inherit
into compatible driver tables. This RFC preserves that model for named driver
instances.

Gateway settings fall into three categories:

| Category | Examples | Behavior |
|---|---|---|
| Gateway-only settings | `bind_address`, `health_bind_address`, `log_level`, `compute_drivers`, `default_compute_driver`, `tls`, `oidc`, `auth`, `gateway_jwt` | Never passed to driver config. |
| Shared driver defaults | `default_image`, `supervisor_image`, `sandbox_namespace`, `guest_tls_ca`, `guest_tls_cert`, `guest_tls_key`, `host_gateway_ip` | Inherited into compatible driver instances through a per-kind allowlist. |
| Driver-instance-only settings | `kind`, `endpoint`, `network_name`, `grpc_endpoint`, `enable_bind_mounts`, `sandbox_pids_limit` | Must appear under `[openshell.drivers.<id>]`; never inherited. |

The gateway resolves `kind`, removes registry-only fields such as `kind`, merges
the kind-specific inherited defaults, and then deserializes the remaining table
with the target driver's existing typed config.

Endpoint configuration is never inherited. A backend endpoint identifies a
specific compute target, so inheriting it into multiple driver IDs would be a
misconfiguration risk. `grpc_endpoint` also remains driver-instance-only because
callback routing may differ per backend.

`sandbox_namespace` remains inheritable. Operators should override it when two
same-kind drivers target the same backend, so watch and reconciliation filters
do not overlap unnecessarily.

### Docker Endpoint Configuration

The Docker driver gains an optional nested `endpoint` table. If omitted, Docker
uses the current local-default connection behavior.

Local socket:

```toml
[openshell.drivers.local]
kind = "docker"

[openshell.drivers.local.endpoint]
socket = "/var/run/docker.sock"
```

Remote host:

```toml
[openshell.drivers.lab-a]
kind = "docker"

[openshell.drivers.lab-a.endpoint]
host = "ssh://openshell@lab-a"
```

Remote TCP with Docker daemon TLS:

```toml
[openshell.drivers.lab-b]
kind = "docker"

[openshell.drivers.lab-b.endpoint]
host = "tcp://lab-b:2376"

[openshell.drivers.lab-b.endpoint.tls]
ca = "/etc/openshell/docker/lab-b/ca.pem"
cert = "/etc/openshell/docker/lab-b/cert.pem"
key = "/etc/openshell/docker/lab-b/key.pem"
```

Validation rules:

- `endpoint.socket` and `endpoint.host` are mutually exclusive.
- `endpoint.tls` requires `endpoint.host`.
- `endpoint.tls` is rejected for `ssh://` endpoints.
- If `endpoint` is omitted, the existing local-default Docker connection path is
  used.

The TLS fields in `endpoint.tls` authenticate the gateway to the Docker daemon.
They are distinct from `guest_tls_*`, which authenticate sandbox supervisors
back to the gateway.

Remote Docker daemon callback behavior is not fully specified by this RFC. The
registry and endpoint shape are intended to support it, but a follow-up must
validate how containers created on a remote daemon reliably reach the gateway.
Local Docker entries keep the current callback auto-detection behavior.

### Extension Drivers

`kind = "extension"` represents an operator-managed compute driver process that
implements `compute_driver.proto`. The gateway connects to it but does not
spawn, supervise, restart, or remove it.

Initial extension endpoints support Unix sockets only:

```toml
[openshell.drivers.kyma]
kind = "extension"

[openshell.drivers.kyma.endpoint]
socket = "/run/openshell/kyma-driver.sock"
```

The gateway calls `GetCapabilities` at startup and logs the extension driver's
advertised name and version for local diagnostics. The registry ID remains the
gateway's routing key.

The `--compute-driver-socket` compatibility flag from PR #1703 remains valid
only when the effective registry has exactly one active driver and that driver
is `kind = "extension"`. In that case the flag fills or overrides
`endpoint.socket` according to normal CLI/env precedence.

If no registry is otherwise configured, the flag can synthesize a single
extension entry:

```toml
[openshell.gateway]
compute_drivers = ["extension"]
default_compute_driver = "extension"

[openshell.drivers.extension]
kind = "extension"

[openshell.drivers.extension.endpoint]
socket = "/run/openshell/driver.sock"
```

If more than one active driver is configured, `--compute-driver-socket` is
rejected. The flag is a single-driver compatibility shortcut, not a second
partial registry language.

### Sandbox Placement

Add a public sandbox placement field:

```proto
message SandboxSpec {
  ...
  string compute_driver = 12;
}
```

The CLI exposes it as:

```shell
openshell sandbox create --compute-driver lab-a --from ubuntu
```

Create behavior:

1. Validate the request shape and the syntax of `spec.compute_driver` when set.
2. Resolve the selected driver ID from `spec.compute_driver` or the configured
   default.
3. Materialize the resolved driver ID into `spec.compute_driver` before
   persisting the sandbox.
4. If `spec.template.image` is empty, set it to the selected driver's default
   image.
5. Validate and provision the sandbox through the selected driver instance.

The field is immutable after creation. Moving a sandbox between drivers requires
new migration or reprovisioning semantics and is out of scope.

The CLI should validate only the driver ID syntax locally. The gateway remains
authoritative for whether the driver exists and is active.

### Driver-Specific Sandbox Config

`SandboxTemplate.driver_config` remains an opaque driver-owned struct envelope,
but selection changes from kind-oriented to driver-ID-oriented.

The gateway forwards only the object at
`template.driver_config.<resolved_compute_driver_id>` to the selected driver.
Other keys are ignored. If the selected key exists and is not an object, the
gateway returns `INVALID_ARGUMENT`, matching current behavior for the selected
driver block.

Example:

```json
{
  "lab-a": {
    "mounts": []
  },
  "lab-b": {
    "mounts": []
  }
}
```

A sandbox placed on `lab-a` receives only the `lab-a` block.

There is no kind fallback for custom named drivers. Legacy behavior still works
because legacy driver IDs equal their kind. A sandbox selected for ID `docker`
still reads `template.driver_config.docker`.

The gateway does not reject non-selected keys in this RFC. A future policy or
gateway option may make unexpected driver-config keys strict.

### Compute Router

`ServerState.compute` becomes a router facade over per-driver runtime instances.
The existing single-driver `ComputeRuntime` can remain the worker type, but the
server-facing API should hide the registry.

Conceptually:

```text
ServerState.compute
  -> ComputeRouter
      default_driver_id: "local"
      drivers:
        local -> ComputeRuntime(kind=docker, id=local)
        lab-a -> ComputeRuntime(kind=docker, id=lab-a)
        kyma  -> ComputeRuntime(kind=extension, id=kyma)
```

Routing rules:

- `validate` and `create` route by the resolved `spec.compute_driver`.
- `stop`, `delete`, and any future sandbox lifecycle operation load the
  persisted sandbox and route by its stored `spec.compute_driver`.
- `default_image` resolution is driver-specific and happens after placement is
  resolved.
- Each driver instance runs its own watch and reconciliation path.
- Startup resume and shutdown cleanup run per driver instance and consider only
  sandboxes assigned to that driver.
- Extra gateway listener addresses requested by local drivers are aggregated
  across all active driver instances.

When a watch or reconciliation event from driver `A` references a persisted
sandbox assigned to driver `B`, the gateway ignores the event and logs a warning
with the sandbox ID, source driver ID, and stored driver ID. A driver must not be
allowed to mutate another driver's sandbox record.

The compute-driver protocol does not carry registry IDs. The router knows the
source driver ID from the stream or runtime that produced the event. Backend
labels may include the driver ID in the future for operator diagnostics, but
that is not required for correctness in this RFC.

### Kubernetes Bootstrap Auth

Kubernetes ServiceAccount bootstrap must remain bound to the selected driver.
A projected ServiceAccount token from one Kubernetes driver must not be able to
mint a gateway JWT for a sandbox assigned to another driver.

The target invariant is:

1. Each active `kind = "kubernetes"` driver has a driver ID, namespace, and
   sandbox ServiceAccount.
2. The K8s ServiceAccount authenticator validates a token against exactly one
   active Kubernetes driver context.
3. The resulting sandbox principal carries both the sandbox ID and the driver ID
   internally.
4. `IssueSandboxToken` loads the sandbox and verifies that
   `sandbox.spec.compute_driver` matches the principal's driver ID before
   minting a gateway JWT.

The first implementation may restrict the active registry to at most one
Kubernetes driver. Supporting multiple active Kubernetes driver instances should
be implemented as a separate security-sensitive phase that satisfies the
invariant above.

### Telemetry and Logs

Telemetry reports compute driver kind, not custom driver ID. Custom IDs may
contain environment details such as location, tenant, or machine names.

Examples:

| Driver ID | Kind | Telemetry value |
|---|---|---|
| `local` | `docker` | `docker` |
| `lab-a` | `docker` | `docker` |
| `prod-k8s` | `kubernetes` | `kubernetes` |
| `kyma` | `extension` | `extension` |

Local gateway logs and error messages may include driver IDs because they are
operator-local diagnostics.

## Implementation plan

1. **Registry config model** - Replace the core "configured driver kinds" shape
   with active driver IDs plus per-ID resolved kind. Add
   `default_compute_driver`, driver ID validation, legacy kind inference, and
   config validation for active/default IDs.
2. **Sandbox API and CLI** - Add `SandboxSpec.compute_driver`, add
   `openshell sandbox create --compute-driver <id>`, materialize the default at
   create time, and make the selected ID immutable.
3. **Router facade** - Introduce a compute router owned by `ServerState`.
   Preserve the server-facing compute methods while routing internally to
   per-driver runtime instances by persisted driver ID.
4. **Driver construction** - Build all active driver instances at startup, call
   `GetCapabilities`, fail startup if any active driver fails, and aggregate
   per-driver listener addresses.
5. **Docker endpoint config** - Add nested Docker `endpoint` parsing and
   validation. Preserve existing local-default behavior when omitted. Validate
   remote Docker support separately before documenting it as supported.
6. **Extension integration** - Fold PR #1703's socket connector into
   `kind = "extension"` and keep `--compute-driver-socket` as the single-driver
   compatibility shortcut.
7. **Watch, reconcile, resume, cleanup** - Run per-driver loops. Scope store
   sweeps to sandboxes whose persisted `compute_driver` matches the runtime.
   Ignore and warn on source-driver mismatches.
8. **Kubernetes bootstrap phase** - Initially allow at most one active
   Kubernetes driver, or implement the full principal driver-ID invariant before
   lifting that limit.
9. **Docs and tests** - Update `architecture/compute-runtimes.md`,
   `docs/reference/gateway-config.mdx`,
   `docs/reference/sandbox-compute-drivers.mdx`, and CLI reference examples.
   Add tests for config compatibility, driver ID validation, default
   materialization, routing, driver-config selection, watch mismatch handling,
   startup failure, and `--compute-driver-socket` compatibility.

## Risks

- **Configuration compatibility** - `compute_drivers` changes from a list of
  kinds to a list of IDs. Legacy IDs preserve common configurations, but parser
  and error-message changes must be careful.
- **Router complexity** - Watch, reconciliation, startup resume, and cleanup
  currently assume one driver. Routing mistakes can corrupt sandbox status or
  prune valid records. Per-driver scoping and mismatch tests are required.
- **Remote Docker uncertainty** - The motivating future use case includes
  remote Docker machines, but callback routing from remote containers to the
  gateway is not fully specified here. The RFC must not over-promise remote
  Docker support before it is validated.
- **Kubernetes auth boundary** - Multiple Kubernetes drivers introduce a
  security-sensitive identity binding problem. The first implementation should
  either enforce the full driver-ID invariant or cap active Kubernetes drivers
  to one.
- **Host-specific driver_config** - Driver config keyed by ID is explicit, but
  ignored non-selected keys may still hide user mistakes. Strict handling can be
  added later as a policy or gateway option.
- **Partial availability** - This RFC fails gateway startup if any active
  driver fails to initialize. That is clear operationally, but it means one
  broken optional backend can prevent the gateway from starting until optional
  or degraded drivers are designed.
- **Extension trust boundary** - Extension drivers run outside the gateway
  process. Socket filesystem permissions remain the trust boundary, and
  operators must provision those permissions correctly.

## Alternatives

### Keep One Gateway per Backend

Operators can run one gateway for each Docker host, Kubernetes cluster, or
extension driver. This avoids a registry but moves placement into gateway
selection and duplicates gateway identity, auth, policy, and client
registration. It also does not give persisted sandboxes a stable compute-driver
routing field.

### Docker-Only Multi-Context Support

A narrower feature could add multiple Docker contexts without changing the
general compute model. That solves one use case but leaves extension drivers,
mixed built-in drivers, and future scheduling work without a coherent naming
boundary. The registry is the smaller long-term abstraction.

### Use Docker Context Names as the Primary Config

Docker contexts are convenient for humans, but they depend on Docker CLI state,
context files, SSH configuration, and credential locations. A long-running
gateway should use explicit endpoint configuration as its durable substrate.
Docker context import can be considered later as a convenience.

### Kind-Keyed Driver Config Fallback

The gateway could fall back from `template.driver_config.<id>` to
`template.driver_config.<kind>`. That makes same-kind instances accidentally
share host-specific settings such as mounts or CDI devices. This RFC keeps
driver config ID-only and treats portable resource design as separate work.

### Add Driver ID to `compute_driver.proto`

Every driver RPC could carry the gateway registry ID. That leaks a gateway-local
routing concern into the driver protocol and forces external drivers to preserve
fields they do not need. The router already knows which runtime produced each
event, so the protocol does not need to change.

### Multi-Driver CLI Activation Now

`--drivers docker,podman --default-compute-driver docker` could synthesize
multiple legacy ID entries. It is useful for quick experiments, but it cannot
represent duplicate Docker instances or per-instance endpoints. This RFC keeps
CLI activation to one ID and leaves multi-ID CLI activation as follow-up.

## Prior art

- RFC 0003 defines the TOML gateway configuration file, driver tables, and
  shared driver default inheritance. This RFC extends that shape from
  kind-named driver tables to ID-named driver instances.
- RFC 0004 calls out driver prefiltering and notes that multiple configured
  compute drivers change gateway assumptions that currently require exactly one
  driver.
- PR #1703 adds an out-of-tree compute-driver socket path and deliberately
  defers name-keyed registry semantics. This RFC provides that registry and
  renames the registry-level kind to `extension`.
- Kubernetes and Docker both separate stable user-facing names from backend
  implementation details. OpenShell should similarly use a stable driver ID for
  placement while keeping kind-specific configuration behind each driver
  instance.

## Open questions

- What exact callback strategy should remote Docker daemon support require?
  Options include explicit public `grpc_endpoint`, SSH tunneling, gateway-side
  relay helpers, or a documented network prerequisite.
- Which Docker endpoint transports should ship in the first implementation:
  local socket only, TCP/TLS, SSH, or all of them?
- Should the gateway expose `ListComputeDrivers` or a health/capability API for
  UI discovery and operational monitoring?
- When should multiple active Kubernetes driver instances be allowed, and what
  tests are required before lifting the initial one-Kubernetes-driver limit?
- Should non-selected `template.driver_config` keys remain ignored forever, or
  should strict mode be configurable by gateway setting or policy?
- Should backend resources receive an `openshell.ai/compute-driver-id` label for
  operator diagnostics even though the protocol does not require it?
- Should `--drivers` eventually accept multiple IDs together with an explicit
  `--default-compute-driver`?
