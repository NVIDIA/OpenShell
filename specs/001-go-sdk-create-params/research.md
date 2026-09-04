# Research: Go SDK Create() Params Struct

## Current Create() Signature

**File**: `sdk/go/openshell/v1/sandbox.go:55-69`

```go
Create(ctx context.Context, workspace, name string, spec *SandboxSpec, labels map[string]string, opts ...CreateOptions) (*Sandbox, error)
```

5 positional params + variadic. The issue (#2807) references the post-#2781 state which adds more positional params. The current signature already benefits from bundling `spec` and `labels` into a creation struct.

- Decision: Proceed with the refactoring on the current codebase. The struct approach works regardless of whether #2781 lands first or after.
- Rationale: The core problem (SandboxSpec reuse for creation and resolved state) exists today. Fixing it now provides a clean foundation for #2781.

## SandboxSpec Type

**File**: `sdk/go/openshell/v1/types/sandbox.go:23-31`

Fields: LogLevel, Environment, Template (*SandboxTemplate), Providers, GPUCount, Policy.

`SandboxTemplate` (line 43) contains `DriverConfig` which is a gateway-resolved field that callers should not set.

- Decision: CreateSandboxParams will contain the same creation-appropriate fields but as flat fields, not wrapping SandboxSpec. This prevents callers from accessing Template.DriverConfig.
- Rationale: A wrapper around SandboxSpec would still expose DriverConfig through the Template field.
- Alternative rejected: Using SandboxSpec directly with documentation-only "don't set DriverConfig" warnings. Compile-time safety beats documentation.

## CreateOptions Type

**File**: `sdk/go/openshell/v1/types/options.go:9-11`

Only field: `Annotations map[string]string`. Retained as-is in the new signature.

## CreateFromTemplate

Does not exist in the current codebase. FR-006 from the spec is not applicable.

- Decision: Skip CreateFromTemplate work.
- Rationale: No method to refactor.

## Call Sites (6 unique locations)

1. `sdk/go/openshell/v1/sandbox_client.go:28` - real client implementation
2. `sdk/go/openshell/v1/fake/sandbox.go:277` - fake client implementation
3. `sdk/go/openshell/v1/fake/fake_test.go:41` - fake test
4. `sdk/go/openshell/v1/integration_test.go:53` - integration test
5. `sdk/go/openshell/v1/doc.go:24,280` - doc examples
6. `sdk/go/README.md:55` and `sdk/go/docs/src/error-handling.md:58` - documentation

## Converter Layer

**File**: `sdk/go/openshell/v1/internal/converter/sandbox.go`

- `SandboxSpecToProto(spec)` converts domain SandboxSpec to proto SandboxSpec
- `SandboxSpecToProtoChecked(spec)` with validation (used in Create)
- `SandboxFromProto(resp)` converts proto response to domain Sandbox

The converter needs a new function to map CreateSandboxParams to proto CreateSandboxRequest fields.

## Proto CreateSandboxRequest

**File**: `proto/openshell.proto:932-942`

Fields: spec (SandboxSpec), name, labels (map), annotations (map), workspace.

The proto SandboxSpec includes: log_level, environment, template, policy, providers, resource_requirements.

## Field Mapping: CreateSandboxParams to Proto

| CreateSandboxParams field | Proto destination |
|--------------------------|-------------------|
| LogLevel | spec.log_level |
| Environment | spec.environment |
| Template (name only) | spec.template.name |
| Providers | spec.providers |
| GPUCount | spec.resource_requirements.gpu |
| Policy | spec.policy |
| Labels (from method param) | labels (top-level) |
