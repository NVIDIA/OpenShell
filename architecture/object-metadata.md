# Object Metadata Convention

## Overview

OpenShell adopts a Kubernetes-style object metadata convention for all top-level domain objects. This standardizes how resources are identified, labeled, and queried across the platform. All resources that users interact with directly (Sandbox, Provider, SshSession, InferenceRoute) follow this convention.

## Core Principles

### 1. Uniform Metadata Structure

All top-level objects embed a common `ObjectMeta` message containing:

- **Stable ID**: Server-generated UUID that never changes
- **Human-readable name**: User-friendly identifier (unique per object type)
- **Creation timestamp**: Milliseconds since Unix epoch
- **Labels**: Key-value pairs for filtering and organization

### 2. Trait-Based Access

Rather than accessing metadata fields directly (e.g., `sandbox.metadata.as_ref().unwrap().id`), code uses trait methods from `openshell_core::metadata`:

```rust
use openshell_core::{ObjectId, ObjectName, ObjectLabels};

let id = sandbox.object_id();        // Returns &str
let name = sandbox.object_name();    // Returns &str
let labels = sandbox.object_labels(); // Returns Option<HashMap<String, String>>
```

This provides:

- **Uniform API** across all object types
- **Graceful fallback** (returns empty string if metadata is None)
- **Reduced boilerplate** in code that works with multiple object types

### 3. Labels for Organization and Filtering

Labels are key-value metadata attached to objects for:

- **Grouping** related resources (e.g., all dev environment sandboxes)
- **Filtering** in list operations (e.g., show only sandboxes with `team=backend`)
- **Automation** and selection in scripts

## Implementation Pattern

### Protobuf Definition

Define `ObjectMeta` once in `proto/datamodel.proto`:

```protobuf
message ObjectMeta {
  string id = 1;
  string name = 2;
  int64 created_at_ms = 3;
  map<string, string> labels = 4;
}
```

Embed it in top-level objects:

```protobuf
message Sandbox {
  ObjectMeta metadata = 1;
  SandboxSpec spec = 2;
  SandboxStatus status = 3;
  int32 phase = 4;
  int32 current_policy_version = 5;
}
```

**Migration**: When adding metadata to an existing object, shift field numbers to make room for `metadata = 1`. This maintains backward compatibility if done before release.

### Trait Implementation

Implement the three traits for each object in `crates/openshell-core/src/metadata.rs`:

```rust
impl ObjectId for Sandbox {
    fn object_id(&self) -> &str {
        self.metadata.as_ref().map(|m| m.id.as_str()).unwrap_or("")
    }
}

impl ObjectName for Sandbox {
    fn object_name(&self) -> &str {
        self.metadata.as_ref().map(|m| m.name.as_str()).unwrap_or("")
    }
}

impl ObjectLabels for Sandbox {
    fn object_labels(&self) -> Option<HashMap<String, String>> {
        self.metadata.as_ref().map(|m| m.labels.clone())
    }
}
```

**Pattern**: Always return empty string for missing metadata rather than panicking. This makes code resilient to malformed data.

### Persistence Layer

The `Store` trait in `crates/openshell-server/src/persistence/mod.rs` provides three methods for working with objects:

```rust
// Store/retrieve by stable ID
async fn put_message<T: ObjectType + Message + ObjectId + ObjectName>(
    &self,
    message: &T,
) -> Result<(), String>;

async fn get<T: ObjectType + Message>(&self, object_type: &str, id: &str) 
    -> Result<Option<ObjectRecord>, String>;

// Retrieve by human-readable name
async fn get_message_by_name<T: ObjectType + Message + ObjectId + ObjectName>(
    &self,
    name: &str,
) -> Result<Option<T>, String>;
```

**Database schema pattern**: Each object type has:

- `id` column (TEXT PRIMARY KEY) — stable UUID
- `name` column (TEXT UNIQUE NOT NULL) — user-facing name
- `payload` column (BLOB) — serialized protobuf
- `created_at_ms` column (INTEGER) — denormalized from metadata for indexing
- `updated_at_ms` column (INTEGER) — last modification time

### Label Filtering

Label selectors follow Kubernetes conventions:

**Format**: `key1=value1,key2=value2` (comma-separated, AND logic)

**Implementation**:

1. Parse selector into key-value pairs
2. For each object, check that ALL selector labels match
3. Return only objects where every label in the selector exists with the exact value

**SQL pattern** (PostgreSQL with JSONB):

```sql
WHERE labels @> '{"env": "dev", "team": "backend"}'::jsonb
```

**SQL pattern** (SQLite):

```sql
WHERE json_extract(labels, '$.env') = 'dev'
  AND json_extract(labels, '$.team') = 'backend'
```

The `list_with_selector` method on `Store` handles this transparently.

### Validation Rules

Labels must follow Kubernetes naming conventions (enforced in `crates/openshell-server/src/grpc/validation.rs`):

**Label keys**:

- Optional prefix + `/` + name (e.g., `example.com/app` or `app`)
- Prefix: DNS subdomain (lowercase alphanumeric, `-`, `.`, max 253 chars)
- Name: alphanumeric + `-`, `_`, `.`, max 63 chars
- Cannot start or end with `-` or `.`

**Label values**:

- Alphanumeric + `-`, `_`, `.`
- Max 63 characters
- Can be empty string

**Validation functions**:

```rust
validate_label_key(key: &str) -> Result<(), Status>
validate_label_value(value: &str) -> Result<(), Status>
validate_labels(labels: &HashMap<String, String>) -> Result<(), Status>
```

**Validation timing**: Validate at API ingress (gRPC handlers) before persisting. Reject invalid labels immediately rather than storing and failing later.

## CLI Integration

### Creating Objects with Labels

```bash
openshell sandbox create --label env=dev --label team=backend
openshell provider create openai --label project=research
```

**Pattern**: Repeatable `--label key=value` flags parsed into `HashMap<String, String>`.

### Listing with Selectors

```bash
openshell sandbox list --selector env=dev
openshell sandbox list --selector env=dev,team=backend
```

**Display**: Show labels in tabular output when present, or in detail views.

## Testing Requirements

### Unit Tests

Test validation logic for:

- Valid label keys (with and without prefix)
- Invalid keys (bad characters, too long, empty segments)
- Valid label values
- Invalid values (non-alphanumeric, too long)
- Selector parsing

### Integration Tests

Test persistence layer:

- Store object with labels
- Retrieve by name and verify labels present
- Filter with single-label selector
- Filter with multi-label selector (AND logic)
- Empty results for non-matching selector

### E2E Tests

Test full workflow through CLI:

- Create multiple objects with different labels
- List all objects
- Filter by single label
- Filter by multiple labels
- Verify labels persist across gateway restarts

**Location**: `e2e/rust/tests/sandbox_labels.rs` (or equivalent for each object type)

## Migration Checklist

When adding object metadata to a new resource type:

1. **Proto changes**:
   - [ ] Add `ObjectMeta metadata = 1;` field
   - [ ] Shift existing field numbers if needed
   - [ ] Update any references to old id/name fields

2. **Trait implementations**:
   - [ ] Implement `ObjectId` trait
   - [ ] Implement `ObjectName` trait
   - [ ] Implement `ObjectLabels` trait
   - [ ] Add to `crates/openshell-core/src/metadata.rs`

3. **Persistence**:
   - [ ] Add database migration (SQLite + PostgreSQL)
   - [ ] Create `labels` column (JSON/JSONB type)
   - [ ] Migrate existing `id`/`name` to `ObjectMeta`
   - [ ] Update `ObjectType` implementation
   - [ ] Update create/read operations to use new structure

4. **Validation**:
   - [ ] Add label validation in gRPC handlers
   - [ ] Validate on create and update operations
   - [ ] Test validation with unit tests

5. **API updates**:
   - [ ] Add `label_selector` parameter to List RPC
   - [ ] Implement selector filtering in persistence layer
   - [ ] Add `labels` field to Create/Update RPCs

6. **CLI updates**:
   - [ ] Add `--label` flag to create command
   - [ ] Add `--selector` flag to list command
   - [ ] Update completion for label keys (if applicable)
   - [ ] Display labels in list and get output

7. **Tests**:
   - [ ] Unit tests for validation
   - [ ] Integration tests for persistence
   - [ ] E2E tests for CLI workflow

8. **Documentation**:
   - [ ] Update user-facing docs for new flags
   - [ ] Add examples with labels to guides

## Common Patterns

### Creating Objects with Metadata

```rust
use crate::persistence::current_time_ms;

let now_ms = current_time_ms()
    .map_err(|e| Status::internal(format!("get current time: {e}")))?;

let sandbox = Sandbox {
    metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
        id: uuid::Uuid::new_v4().to_string(),
        name: user_provided_name,
        created_at_ms: now_ms,
        labels: request.labels,
    }),
    spec: Some(spec),
    status: None,
    phase: SandboxPhase::Provisioning as i32,
    current_policy_version: 0,
};

// Validate before persisting
validate_object_metadata(sandbox.metadata.as_ref(), "sandbox")?;
store.put_message(&sandbox).await?;
```

### Filtering by Labels

```rust
let sandboxes = if request.label_selector.is_empty() {
    store.list(Sandbox::object_type(), limit, offset).await?
} else {
    validate_label_selector(&request.label_selector)?;
    store.list_with_selector(
        Sandbox::object_type(),
        &request.label_selector,
        limit,
        offset,
    ).await?
};
```

### Accessing Metadata Fields

```rust
use openshell_core::{ObjectId, ObjectName};

// Good: trait-based access
let sandbox_id = sandbox.object_id();
let sandbox_name = sandbox.object_name();

// Avoid: direct field access
let sandbox_id = sandbox.metadata.as_ref().unwrap().id.as_str(); // Don't do this
```

## Anti-Patterns to Avoid

### ❌ Bypassing Validation

```rust
// Bad: storing labels without validation
store.put_message(&sandbox).await?;
```

```rust
// Good: validate before storing
validate_labels(&sandbox.metadata.as_ref().unwrap().labels)?;
store.put_message(&sandbox).await?;
```

### ❌ Direct Field Access

```rust
// Bad: fragile to missing metadata
let id = sandbox.metadata.as_ref().unwrap().id.clone();
```

```rust
// Good: trait-based with fallback
let id = sandbox.object_id().to_string();
```

### ❌ Inconsistent Object Construction

```rust
// Bad: forgetting created_at_ms or labels
let sandbox = Sandbox {
    metadata: Some(ObjectMeta {
        id: uuid::Uuid::new_v4().to_string(),
        name: "test".to_string(),
        ..Default::default()  // Silently sets created_at_ms=0, labels=empty
    }),
    ..Default::default()
};
```

```rust
// Good: explicit fields
let sandbox = Sandbox {
    metadata: Some(ObjectMeta {
        id: uuid::Uuid::new_v4().to_string(),
        name: "test".to_string(),
        created_at_ms: current_time_ms()?,
        labels: request.labels,
    }),
    ..Default::default()
};
```

### ❌ Client-Side ID Generation

```rust
// Bad: letting clients specify IDs
let sandbox = Sandbox {
    metadata: Some(ObjectMeta {
        id: request.id,  // Never trust client-provided IDs
        ..
    }),
    ..
};
```

```rust
// Good: server generates stable IDs
let sandbox = Sandbox {
    metadata: Some(ObjectMeta {
        id: uuid::Uuid::new_v4().to_string(),
        ..
    }),
    ..
};
```

## References

- **Kubernetes API Conventions**: https://kubernetes.io/docs/reference/using-api/api-concepts/
- **Label Syntax**: https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/
- **Proto definition**: `proto/datamodel.proto`
- **Trait implementations**: `crates/openshell-core/src/metadata.rs`
- **Persistence layer**: `crates/openshell-server/src/persistence/mod.rs`
- **Validation logic**: `crates/openshell-server/src/grpc/validation.rs`
- **E2E tests**: `e2e/rust/tests/sandbox_labels.rs`
