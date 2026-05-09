# openshell-core

Shared types, constants, configuration, and helpers used across OpenShell
crates.

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
