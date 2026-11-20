# openshell-driver-sdk

Contract between the gateway and the compute drivers it launches.

The gateway writes one TOML startup document and starts the driver with
`--config <path>`. The document has a `schema_version`, a `[gateway]` table with
a fixed schema, and a `[driver_config]` table that is the operator's
`driver_config` for the selected driver. The gateway does not interpret
`driver_config`; the driver deserializes and validates it.

This crate owns the document types, bounded parsing, and the schema version
check. Where `openshell-core` already defines a type the gateway and drivers
share (OTLP exports), the document
uses it directly, so there is one definition. Those types' serialized form is
part of the contract, and changing it is a schema change. Creating the file with
restrictive permissions and launching the driver belong to the gateway.

## Versioning

A driver accepts exactly the `SCHEMA_VERSION` it was built with and refuses any
other, naming both versions. Bump `SCHEMA_VERSION` for any change that makes an
existing document fail to parse or changes its meaning, including removing or
renaming a field or changing its type.

`tests/fixtures/startup-v1.toml` lists every field the schema defines. A test
parses and re-serializes it and compares the result, so a removed or renamed
field changes the fixture and shows in review. Keep every optional field
populated in it. Machine-checked breaking-change detection is not in place yet.

## Contents

- Network trust is passed as the staged artifact's path, digest, and
  certificate count. The certificate bytes do not cross the process boundary.
- OTLP export headers are secrets and are not in the document.
- `[gateway]` holds only values that come from the gateway itself. Settings an
  operator puts in a driver's table, such as admission, proxy, and the endpoint
  override, stay in `[driver_config]` for the driver to read and validate.
- `gateway_port` lets a driver derive the endpoint sandboxes use to reach the
  gateway.
- Proxy credentials are referenced by file path, not included.
