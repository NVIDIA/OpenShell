# openshell-driver-contract

The documents a compute driver hands to the supervisor and the sandbox boundary.
The driver writes the runtime descriptor and the boundary configuration; the
supervisor and the sandbox boundary read and validate them.

`openshell-driver-sdk` re-exports this crate as `driver_contract`, so a driver
author can depend on the SDK alone. The supervisor and sandbox depend on this
crate directly.

## Modules

| Module | Side | Contents |
|---|---|---|
| `model` | both | The types, with no I/O: `SandboxRuntimeDescriptor`, `BoundaryConfig`, the identity and evidence types, `BackendError` and `BackendDescriptor`, `SandboxSessionId`, `CredentialEpoch`, `SessionRotation`, and the contract constants |
| `write` | driver | Producing what a driver hands over, such as `generate_sandbox_tls_material`. Behind the `write` feature, so that readers do not build the certificate generation code |
| `read` | supervisor and sandbox | What a reader checks before it acts on a document, such as `validate_resource_claims` |

The model types are also re-exported at the crate root. The crate depends on no
other OpenShell crate except `openshell-crypto`, and only with the `write`
feature.

| Type | Produced by | Read by |
|---|---|---|
| `SandboxRuntimeDescriptor` | Driver | Supervisor |
| `BoundaryConfig` | Driver | Sandbox boundary |

`openshell_sandbox_backend::boundary_protocol` and
`openshell_isolation_interface::contract` re-export these types for code outside
this repository.

## The protobuf specification

`proto/sandbox_runtime.proto` specifies the replacement: the same documents as
protobuf messages, written as binary protobuf. It repeats
`ResolvedWorkloadIdentity` and `DriverFenceEvidence` from `compute_driver.proto`,
so it does not import that protocol, and adds `contract_version`, which tells a
new document from a legacy one.
`crates/openshell-core/tests/duplicated_proto_messages.rs` fails if the copies
drift. `build.rs` generates the messages with ordered maps, so that equal
documents encode to equal bytes. They are in `proto::sandbox_runtime`, and
`proto::FILE_DESCRIPTOR_SET` holds the descriptors, which the tests use to turn
the protobuf JSON examples into binary.

`convert` converts between the model types and the messages (`From` into a
message, `TryFrom` back, which applies the validation the legacy readers apply
later). `tests/driver_contract_proto_json.rs` checks both directions against the
protobuf JSON examples in `tests/legacy_contract/proto_json/`: the message built
from a legacy example must equal the protobuf JSON example, and reading the
example, as binary, must give back the legacy example. The examples are the
reference for a driver in any language. Regenerate them from the legacy examples
with `UPDATE_EXAMPLES=1` and review the diff.

## Writing and reading the files

A driver gets the files of a document from `write::encode(&document)`. It
validates the document first, then returns each file's name and bytes: the
binary protobuf file and the legacy JSON file beside it, encoded from the same
value so they cannot disagree. The driver delivers them by whatever means it
uses. The binary file is named like the legacy one with `.pb` in place of
`.json`; the rule and the fallback are internal to this crate.

The supervisor and the sandbox boundary read through `read`:
`read::boundary_config(path)` and `read::runtime_descriptor(path)` take the path
of the legacy file, prefer the binary file beside it, and fall back to the
legacy one. A binary file that exists but is invalid is an error, not a reason to
fall back. `read::consume(path)` removes every form of a single-use document.
`read::descriptor_payload(path, backend)` is transitional: the supervisor still
passes the descriptor to the built-in runtime as a legacy payload, and the
function goes away with the legacy encoding. Other drivers write only the
legacy files, which readers still accept.

`tests/legacy_contract_files.rs` checks the files against the examples.

## The current encoding

The encoding the types produce with `serde` is the format that exists today. It
is not a specification to build on and is expected to be replaced by a
language-neutral one, so it accepts no new fields and is removed once the
replacement has shipped and no supported release reads it. Readers reject
unknown fields, so a writer must not add any, and the documents carry no
version.

`tests/legacy_contract/examples/` holds the golden documents, and
`tests/legacy_contract.rs` checks that each decodes and re-encodes to the same
JSON and that readers reject invalid ones. A change that alters an encoding
fails there.
