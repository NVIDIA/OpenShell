# openshell-driver-sdk

The narrow contract that compute drivers share with `OpenShell` core. It holds
the items that both a crate that stays in core (the gateway, the supervisor, the
Kubernetes driver) and the desktop drivers use, so each constant and type has
one definition.

`openshell-core` re-exports every module and item defined here, so existing
`openshell_core::...` paths keep resolving to the same definitions. Add an item
to this crate only when something that stays in core also needs it. Code used
only by the Docker, Podman, and VM drivers belongs in
`openshell-container-runtime`.

## Contents

- `proto`: the generated compute-driver contract (`compute_driver.proto` and the
  protos it imports) and the git-derived build `VERSION`.
- `sandbox_env`, `container_paths`, `driver_mounts`, `driver_utils`,
  `resource_admission`, `gpu`, `config`: the sandbox environment protocol and
  the validation shared by drivers and the supervisor.
- `jwt` (feature `jwt`), `extension_protocol`, `network_trust`, `policy`: tokens,
  extension negotiation, destination-trust bundles, and the sandbox workload
  identity limits.
- `error`, `paths`, `net`, `settings`, `telemetry`, `time`, `progress`,
  `image`, `sandbox_session`, `sandbox_generation`, `proto_struct`,
  `external_driver_socket`, `e2fsprogs`: small helpers.
- `legacy_contract` (feature `legacy-contract`): the Rust-defined documents a
  driver hands to the supervisor and the sandbox boundary. See below.

## Dependencies

The crate depends only on workspace crates and crates.io, and never on
`openshell-core`.

## Legacy driver contract

A compute driver provisions two things for the supervisor and the sandbox
boundary besides the `ComputeDriver` gRPC service: the JSON documents below, and
a few constants. `legacy_contract` holds the Rust types for them so that a
driver does not depend on `openshell-core` or `openshell-sandbox-backend`.

| Type | Produced by | Read by |
|---|---|---|
| `jwt::SandboxLaunchAuthentication` | Gateway | Driver |
| `jwt::SupervisorAuthBundle` | Gateway, inside the launch authentication | Supervisor |
| `SandboxRuntimeDescriptor` | Driver | Supervisor |
| `BoundaryConfig` | Driver | Sandbox boundary |

The module also holds the backend name, the resource claim keys and the
supervisor CA paths that drivers set, and `generate_sandbox_tls_material`.

This is the format that exists today, not a specification to build on. It is
expected to be replaced by a language-neutral one, so the module accepts no new
fields and is removed once the replacement has shipped and no supported release
reads it. Readers reject unknown fields, so a writer must not add any, and the
documents carry no version.

`tests/legacy_contract/examples/` holds the golden documents, and
`tests/legacy_contract.rs` checks that each decodes and re-encodes to the same
JSON and that readers reject invalid ones. A change that alters an encoding
fails there.

### Replacing it

Options considered for the replacement are JSON Schema for these documents, and
protobuf messages written as proto3 JSON. JSON Schema describes today's bytes
exactly but is a second description of concepts that protos already define;
protobuf avoids that, and a driver that serializes generated types would emit
proto3 JSON, which existing readers reject. Nothing is decided.

A lower-risk path than reading both formats is to write both: a driver writes
the new format under a new file name beside the legacy one, and the supervisor
and sandbox prefer the new file when present. Every document is regenerated at
each create and restart, so there is no stored data to migrate. The gateway's
launch authentication travels over gRPC, so it can gain a typed message field
beside the opaque bytes instead of a new JSON form. Docker rewrites its own
`BoundaryConfig` and descriptor in place at restart; it would first need to keep
its restart state privately, as Podman does, so that a driver never parses a
file written by an older one.
