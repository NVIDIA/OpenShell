# openshell-core

Shared types, constants, configuration, and helpers used across OpenShell
crates.

## Isolation registrations

`isolation_registration` owns the operator registry's backend names, byte-stream
endpoints, and shared validation. Its fallible conversions carry registrations
through the compute-driver protobuf and back into the supervisor's JSON launch
file. These routes contain no credentials or driver-owned launch coordinates.

## Object Metadata

Top-level user-facing objects use a Kubernetes-style metadata convention. The
metadata shape provides:

- Stable server-generated ID.
- Human-readable name.
- Creation timestamp.
- Optional labels for filtering and automation.

Code that works with object metadata should use the traits in
`openshell_core::metadata` instead of reaching into protobuf fields directly:

```rust
use openshell_core::{ObjectId, ObjectLabels, ObjectName};

let id = sandbox.object_id();
let name = sandbox.object_name();
let labels = sandbox.object_labels();
```

Trait methods must tolerate missing metadata and return safe empty values rather
than panicking.

## Label Rules

Labels follow Kubernetes-style key and value conventions:

- Keys may include an optional DNS-prefix followed by `/`.
- Names are limited to alphanumeric characters plus `-`, `_`, and `.`.
- Values use the same character set and may be empty.
- Selectors use comma-separated `key=value` pairs with AND semantics.

Validate labels at API ingress before persisting objects.

## Inference Profiles

Provider inference profiles live in this crate so the gateway, sandbox, and
router agree on provider defaults. Profiles define:

- Auth header style.
- Default upstream headers.
- Client-supplied passthrough headers.
- Supported inference protocol shapes.

Do not duplicate provider-specific inference behavior in callers. Add shared
behavior here, then consume it from the gateway, sandbox, and router.

## Static Credential Resolution

Static credential bindings carry both an endpoint boundary and a placement
boundary. `provider_credentials` compiles them together and preserves placement
when creating a request-scoped resolver. Request rewriting supplies the actual
header name, query key, or path slot before resolving each reference. Missing or
unsupported placement fails closed.

Header placement authorizes a header name independently of authentication
scheme. Basic authentication applies the same check before resolving decoded
references. Body and WebSocket rewriting cannot override a credential's declared
placement. Signing-only material uses the supervisor's trusted signing path.

Placement changes are authorization changes: retained references and stable
handles must not retain access to the previous placement.

## Middleware Contracts

Built-in supervisor middleware identifiers, host-selector matching, and pure
configuration validation live in `openshell_core::middleware`. Policy admission
and the supervisor runtime consume the same contract without introducing a
dependency from the policy crate to the supervisor implementation.

## Optional Compute Updates

The generated `proto::compute::v1::compute_driver_server::ComputeDriver` trait
retains its baseline methods and streaming associated type. Supporting external
drivers additionally serve `ComputeDriverConfigurationUpdates` on the same
endpoint and advertise `openshell.compute.update-sandbox-configuration`.
The request carries image and lifecycle preconditions plus optional command and
environment replacements. Drivers without the capability need no new method.

Linked drivers opt in through `openshell_core::compute::ComputeDriver` and
`ComputeDriverFactory::build_with_configuration_updates`. The default factory
hook calls `build` without an updater. Registration and capability negotiation
are both required. Metadata-only updates are handled by the gateway.

## Protobuf Struct Conversion

Use `openshell_core::proto_struct` when crossing between `serde_json` values and
`prost_types::{Struct, Value}`. Both conversion directions live in this module;
JSON-to-protobuf conversion is fallible so callers cannot silently replace an
unrepresentable number.
