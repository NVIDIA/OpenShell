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

### The replacement format

`proto/sandbox_runtime.proto` specifies the replacement: the same documents as
protobuf messages, written as canonical protobuf JSON. It reuses
`ResolvedWorkloadIdentity` and `DriverFenceEvidence` from `compute_driver.proto`
and adds `contract_version`, which tells a new document from a legacy one. The
generated types are in `proto::sandbox_runtime`, and `proto::FILE_DESCRIPTOR_SET`
holds the descriptors for a reader or writer that works with the JSON directly.

`legacy_contract::convert` converts between the legacy types and the messages
(`From` into a message, `TryFrom` back, which applies the validation the legacy
readers apply later). `tests/driver_contract_proto_json.rs` checks both
directions against the examples in `tests/legacy_contract/proto_json/`: the
message built from a legacy example must equal the protobuf JSON example, and
reading the protobuf JSON example must give back the legacy example. The
examples are the reference for a driver in any language. Regenerate them from
the legacy examples with `UPDATE_EXAMPLES=1` and review the diff.

The Docker driver writes the new files beside the legacy ones, and the
supervisor and the sandbox boundary prefer them (see `legacy_contract::document`
and the file naming rule in `proto/README.md`). A driver gets both files of a
document from one value with `ContractDocument::to_files`, so they cannot
disagree, and delivers them by its own means; the supervisor reads the built-in
descriptor with `read_descriptor_payload`. Other drivers write only the legacy
files, which readers still accept.

### Migrating

The replacement is protobuf messages written as protobuf JSON, chosen over JSON
Schema. JSON Schema describes today's bytes exactly but is a second description
of concepts that the protos already define. Protobuf JSON is not the encoding in
use (tags, key casing, `oneof` shape, string-encoded 64-bit integers), so a
driver that serialized the generated types would write documents that existing
readers reject. That is why a reader tells the two formats apart by
`contract_version`.

A lower-risk path than reading both formats is to write both: a driver writes
the new format under a new file name beside the legacy one, and the supervisor
and sandbox prefer the new file when present. Every document is regenerated at
each create and restart, so there is no stored data to migrate. The gateway's
launch authentication travels over gRPC, so it can gain a typed message field
beside the opaque bytes instead of a new JSON form. Docker rewrites its own
`BoundaryConfig` and descriptor in place at restart; it would first need to keep
its restart state privately, as Podman does, so that a driver never parses a
file written by an older one.
