# Data Model: Go SDK Create() Params Struct

## Entities

### CreateSandboxParams (NEW)

Represents creation intent for a sandbox. Value type, not pointer. Zero value is valid (all fields optional).

| Field | Type | Description |
|-------|------|-------------|
| Spec | *SandboxSpec | Full sandbox specification (workload config, template, etc.) |
| Labels | map[string]string | User-defined labels for the sandbox |

Note: The struct wraps the existing `*SandboxSpec` pointer and `labels` map that were previously positional parameters. This preserves the existing field semantics while bundling them into a single parameter. The `SandboxSpec` type already exists and contains: LogLevel, Environment, Template, Providers, GPUCount, Policy. The `Template.DriverConfig` field within SandboxSpec is a pre-existing concern tracked separately.

### SandboxSpec (UNCHANGED)

Existing type representing sandbox specification. Used both in CreateSandboxParams (as creation input) and in the resolved Sandbox (as returned state).

| Field | Type | Description |
|-------|------|-------------|
| LogLevel | string | Logging verbosity |
| Environment | map[string]string | Environment variables |
| Template | *SandboxTemplate | Template configuration (includes DriverConfig) |
| Providers | []string | Provider names |
| GPUCount | int | GPU resource count |
| Policy | *SandboxPolicy | Security policy |

### CreateOptions (UNCHANGED)

Cross-cutting creation options, retained as variadic parameter.

| Field | Type | Description |
|-------|------|-------------|
| Annotations | map[string]string | Metadata annotations |

## Relationships

```
Create(ctx, workspace, name, CreateSandboxParams, ...CreateOptions)
                                    |
                                    ├── Spec *SandboxSpec (existing type)
                                    └── Labels map[string]string

Converter: CreateSandboxParams → proto CreateSandboxRequest
                                    |
                                    ├── spec field → SandboxSpecToProto(params.Spec)
                                    ├── labels field → req.Labels
                                    ├── name → req.Name (from positional)
                                    └── workspace → req.Workspace (from positional)
```

## Converter Changes

A new converter function maps the creation struct to proto:

```
CreateSandboxParamsToProto(params CreateSandboxParams) → fields for CreateSandboxRequest
```

This delegates to the existing `SandboxSpecToProtoChecked` for the Spec field and maps Labels directly.
