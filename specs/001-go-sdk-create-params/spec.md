# Feature Specification: Go SDK Create() Params Struct

**Feature Branch**: `6116-go-sdk-create-params`

**Created**: 2026-09-04

**Status**: Draft

**Input**: Bundle positional parameters in Go SDK's SandboxInterface.Create() into a typed creation struct, separating creation intent from resolved state.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Create sandbox with readable call site (Priority: P1)

A Go SDK consumer creates a sandbox by passing a structured params object instead of multiple positional arguments. The call site clearly communicates which fields are set and which are omitted, without requiring knowledge of parameter ordering.

**Why this priority**: This is the core value proposition. Every Create() caller benefits from improved readability and type safety.

**Independent Test**: Can be tested by writing a Go program that calls Create() with a CreateSandboxParams struct containing only a workload config, verifying the sandbox is created successfully.

**Acceptance Scenarios**:

1. **Given** a Go SDK client, **When** calling Create() with a CreateSandboxParams struct containing only Workload set, **Then** the sandbox is created with default values for Policy, Providers, and Labels.
2. **Given** a Go SDK client, **When** calling Create() with an empty CreateSandboxParams{}, **Then** the sandbox is created with all optional fields at their zero values.
3. **Given** a Go SDK client, **When** calling Create() with all CreateSandboxParams fields populated, **Then** all fields are correctly passed to the gateway.

---

### User Story 2 - Type safety prevents setting gateway-only fields (Priority: P1)

A Go SDK consumer cannot accidentally set gateway-resolved fields (such as DriverConfig) when creating a sandbox, because CreateSandboxParams only exposes fields appropriate for creation intent.

**Why this priority**: Equally critical as readability. Prevents a class of bugs where callers set fields that the gateway silently discards.

**Independent Test**: Can be tested by verifying that CreateSandboxParams has no DriverConfig field at compile time.

**Acceptance Scenarios**:

1. **Given** the CreateSandboxParams type definition, **When** a developer attempts to set a DriverConfig field, **Then** the code fails to compile.
2. **Given** the CreateSandboxParams type definition, **When** inspecting its exported fields, **Then** only creation-appropriate fields are present (Workload, Policy, Providers, Labels).

---

### User Story 3 - Existing tests and examples migrate cleanly (Priority: P2)

All existing call sites in tests, examples, and internal code are updated to use the new struct-based signature without behavioral changes.

**Why this priority**: Migration must be complete and non-breaking within the SDK. Partial migration would leave inconsistent API patterns.

**Independent Test**: Can be tested by running the full Go SDK test suite after migration and verifying all tests pass.

**Acceptance Scenarios**:

1. **Given** the updated Create() signature, **When** running `go test ./...` in the SDK directory, **Then** all existing tests pass.
2. **Given** the updated Create() signature, **When** running `go vet ./...`, **Then** no type errors or warnings are reported.

---

### Edge Cases

- What happens when CreateSandboxParams is passed as a nil pointer? Decision: use a value type (not pointer), so zero value is always valid.
- How does CreateFromTemplate() handle the same pattern? It should receive its own params struct if it has similar positional parameter issues.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The SDK MUST provide a `CreateSandboxParams` struct type that bundles optional creation fields: Workload, Policy, Providers, and Labels.
- **FR-002**: The `SandboxInterface.Create()` method MUST accept `CreateSandboxParams` as a value parameter (not pointer) replacing the individual positional parameters for workload, policy, providers, and labels.
- **FR-003**: The `CreateSandboxParams` struct MUST NOT include any gateway-resolved fields such as DriverConfig, Template resolution state, or status fields.
- **FR-004**: The `Create()` method MUST retain `ctx`, `workspace`, and `name` as positional parameters before the params struct.
- **FR-005**: The `Create()` method MUST retain the existing `...CreateOptions` variadic parameter after the params struct.
- **FR-006**: If `CreateFromTemplate()` has a similar multi-positional-parameter signature, it MUST receive an analogous params struct following the same pattern.
- **FR-007**: All existing call sites (tests, examples, internal SDK code) MUST be updated to use the new signature.
- **FR-008**: The existing `SandboxSpec` type used for resolved sandbox state MUST remain unchanged.

### Key Entities

- **CreateSandboxParams**: A struct representing creation intent for a sandbox, containing only fields that callers should set. Value type (not pointer) so zero value is a valid empty configuration.
- **SandboxSpec**: The existing type representing gateway-resolved sandbox state. Unchanged by this feature.
- **CreateOptions**: The existing variadic options type for cross-cutting creation concerns (e.g., Annotations). Unchanged by this feature.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: All Create() call sites use the struct-based signature with no positional nilable parameters.
- **SC-002**: The full Go SDK test suite passes after migration (`go test ./...` exits 0).
- **SC-003**: No gateway-resolved fields are accessible on CreateSandboxParams (verified by code inspection and compile-time checks).
- **SC-004**: The Create() method signature has at most 5 parameters: ctx, workspace, name, params, opts.

## Assumptions

- The Go SDK's SandboxInterface is the primary interface affected. Other domain clients (Provider, Workspace, etc.) are not in scope.
- CreateSandboxParams uses Go value semantics (not a pointer), matching the convention where zero-value structs represent "use defaults."
- The existing CreateOptions variadic parameter is retained as-is for cross-cutting concerns like Annotations.
- This change is breaking for Go SDK callers. Since the SDK is pre-1.0, breaking changes are acceptable.
- The converter layer between domain types and proto types may need updates to map from CreateSandboxParams to the proto CreateSandboxRequest.
