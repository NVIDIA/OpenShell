# Quickstart Validation: Go SDK Create() Params Struct

## Prerequisites

- Go 1.22+ installed
- Repository cloned and on branch `6116-go-sdk-create-params`

## Validation Scenarios

### 1. Compile-time verification

Verify the new signature compiles and all call sites are updated:

```shell
cd sdk/go
go build ./...
go vet ./...
```

**Expected**: Both commands exit 0 with no errors.

### 2. Unit test suite

Run the full Go SDK test suite to verify behavioral equivalence:

```shell
cd sdk/go
go test ./...
```

**Expected**: All tests pass. No test should need behavioral changes, only signature updates.

### 3. Empty params (zero value)

Verify that an empty `CreateSandboxParams{}` works the same as passing `nil, nil` for spec and labels in the old signature:

```go
sandbox, err := client.Sandboxes().Create(ctx, "default", "test",
    types.CreateSandboxParams{},
)
```

**Expected**: Creates a sandbox with default spec and no labels.

### 4. Fully populated params

Verify all fields pass through correctly:

```go
sandbox, err := client.Sandboxes().Create(ctx, "default", "test",
    types.CreateSandboxParams{
        Spec: &types.SandboxSpec{
            LogLevel: "debug",
            Providers: []string{"openai"},
        },
        Labels: map[string]string{"env": "test"},
    },
)
```

**Expected**: Sandbox created with the specified spec and labels.

### 5. Coverage test passes

Verify the existing coverage test (which catches unmapped fields) still passes:

```shell
cd sdk/go
go test ./openshell/v1/internal/converter/ -run TestCoverage
```

**Expected**: Coverage test passes, confirming the new type's fields are handled by the converter.
