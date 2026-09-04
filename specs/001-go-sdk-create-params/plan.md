# Implementation Plan: Go SDK Create() Params Struct

**Branch**: `6116-go-sdk-create-params` | **Date**: 2026-09-04 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `specs/001-go-sdk-create-params/spec.md`

## Summary

Replace the Go SDK's `SandboxInterface.Create()` positional parameters with a `CreateSandboxParams` struct that bundles creation-intent fields. This separates creation input from the resolved `SandboxSpec` type, preventing callers from accidentally setting gateway-only fields like `DriverConfig`. The converter layer gets a new function to map the creation struct to proto fields.

## Technical Context

**Language/Version**: Go 1.22+

**Primary Dependencies**: gRPC, Connect, protobuf, testify

**Storage**: N/A

**Testing**: `go test ./...` (unit tests with bufconn, testify assertions)

**Target Platform**: Library (Go SDK consumed by CLI, TUI, and external callers)

**Project Type**: Library

**Performance Goals**: N/A (type-level refactor, no runtime behavior change)

**Constraints**: Must be backward-incompatible (breaking change). SDK is pre-1.0, so acceptable.

**Scale/Scope**: 6 call sites to update, 3 files to modify for the core change, plus docs

## Constitution Check

Constitution is a template (not filled in for this project). No gates to evaluate.

## Project Structure

### Documentation (this feature)

```text
specs/001-go-sdk-create-params/
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
└── checklists/
    └── requirements.md
```

### Source Code (repository root)

```text
sdk/go/openshell/v1/
├── types/
│   ├── sandbox.go          # Add CreateSandboxParams type
│   └── options.go          # CreateOptions (unchanged)
├── sandbox.go              # Update SandboxInterface.Create() signature
├── sandbox_client.go       # Update real client implementation
├── fake/
│   ├── sandbox.go          # Update fake client implementation
│   └── fake_test.go        # Update test call sites
├── integration_test.go     # Update test call sites
├── doc.go                  # Update doc examples
├── internal/converter/
│   └── sandbox.go          # Add CreateSandboxParamsToProto converter
└── README.md               # Update example code

sdk/go/docs/src/
└── error-handling.md       # Update example code
```

**Structure Decision**: All changes are within the existing `sdk/go/` directory tree. No new directories needed. The new `CreateSandboxParams` type goes in `types/sandbox.go` alongside the existing `SandboxSpec`.
