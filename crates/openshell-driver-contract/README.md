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
