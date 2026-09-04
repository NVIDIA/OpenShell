# Tasks: Go SDK Create() Params Struct

**Input**: Design documents from `specs/001-go-sdk-create-params/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

## Phase 1: Setup

**Purpose**: No project setup needed. This is a refactor within an existing SDK.

(No tasks in this phase)

---

## Phase 2: Foundational (New Type + Converter)

**Purpose**: Create the new CreateSandboxParams type and its converter. These MUST be complete before updating any signatures or call sites.

- [x] T001 Define CreateSandboxParams struct in sdk/go/openshell/v1/types/sandbox.go with fields: Spec *SandboxSpec, Labels map[string]string
- [x] T002 Add CreateSandboxParamsToProto converter function in sdk/go/openshell/v1/internal/converter/sandbox.go that maps Spec via existing SandboxSpecToProtoChecked and Labels directly
- [x] T003 Add unit test for CreateSandboxParamsToProto in sdk/go/openshell/v1/internal/converter/sandbox_test.go covering: empty params, spec-only, labels-only, fully populated

**Checkpoint**: New type and converter exist, tested, but not yet wired into the interface.

---

## Phase 3: User Story 1 - Readable call sites (Priority: P1)

**Goal**: Update SandboxInterface.Create() to accept CreateSandboxParams, making call sites readable.

**Independent Test**: Call Create() with a CreateSandboxParams struct, verify sandbox creation succeeds.

- [x] T004 [US1] Update SandboxInterface.Create() signature in sdk/go/openshell/v1/sandbox.go to accept CreateSandboxParams as value parameter replacing spec and labels positional params
- [x] T005 [US1] Update real client implementation in sdk/go/openshell/v1/sandbox_client.go to use CreateSandboxParams, calling CreateSandboxParamsToProto in the converter
- [x] T006 [US1] Update fake client implementation in sdk/go/openshell/v1/fake/sandbox.go to match new interface signature
- [x] T007 [P] [US1] Update fake client tests in sdk/go/openshell/v1/fake/fake_test.go to use CreateSandboxParams
- [x] T008 [P] [US1] Update integration test in sdk/go/openshell/v1/integration_test.go to use CreateSandboxParams
- [x] T009 [P] [US1] Update doc examples in sdk/go/openshell/v1/doc.go to use CreateSandboxParams

**Checkpoint**: All Go code compiles. `go build ./...` and `go vet ./...` pass in sdk/go.

---

## Phase 4: User Story 2 - Type safety (Priority: P1)

**Goal**: Verify that CreateSandboxParams does not expose gateway-resolved fields.

**Independent Test**: Confirm CreateSandboxParams has no DriverConfig field at compile time.

- [x] T010 [US2] Verify CreateSandboxParams type exposes only creation-appropriate fields (Spec, Labels) by reviewing the type definition from T001. No DriverConfig field exists directly on CreateSandboxParams. Document that DriverConfig is still accessible through Spec.Template.DriverConfig (pre-existing concern tracked separately in issue #2807 comments).

**Checkpoint**: Type safety verified.

---

## Phase 5: User Story 3 - Migration completeness (Priority: P2)

**Goal**: All documentation examples updated to match the new signature.

**Independent Test**: Full Go SDK test suite passes after migration.

- [x] T011 [P] [US3] Update README example in sdk/go/README.md to use CreateSandboxParams
- [x] T012 [P] [US3] Update error handling docs example in sdk/go/docs/src/error-handling.md to use CreateSandboxParams

**Checkpoint**: All call sites (code + docs) use the new signature. `go test ./...` passes.

---

## Phase 6: Polish & Validation

**Purpose**: Final validation and cleanup.

- [x] T013 Run full Go SDK test suite: `cd sdk/go && go test ./...`
- [x] T014 Run Go vet and build checks: `cd sdk/go && go vet ./... && go build ./...`
- [x] T015 Run quickstart.md validation scenarios

---

## Dependencies & Execution Order

### Phase Dependencies

- **Foundational (Phase 2)**: No dependencies, start immediately
- **User Story 1 (Phase 3)**: Depends on T001, T002, T003 (Foundational)
- **User Story 2 (Phase 4)**: Depends on T001 (type definition only)
- **User Story 3 (Phase 5)**: Can run in parallel with Phase 3/4 (docs are independent files)
- **Polish (Phase 6)**: Depends on all prior phases

### Within Phase 3 (User Story 1)

- T004 (interface) must complete before T005, T006
- T005, T006 (implementations) must complete before T007, T008, T009
- T007, T008, T009 are parallelizable (different test files)

### Parallel Opportunities

- T007, T008, T009 can run in parallel (different test files)
- T011, T012 can run in parallel (different doc files)
- Phase 4 (US2) and Phase 5 (US3) can run in parallel with Phase 3 after T001

---

## Implementation Strategy

### MVP First (User Story 1)

1. Complete Phase 2: Foundational (T001-T003)
2. Complete Phase 3: User Story 1 (T004-T009)
3. **VALIDATE**: `go test ./...` passes
4. Remaining phases are cleanup and verification

### Incremental Delivery

1. T001-T003: Type + converter + tests (foundation)
2. T004-T009: Interface + all implementations (core change)
3. T010: Type safety verification
4. T011-T012: Doc updates
5. T013-T015: Final validation
