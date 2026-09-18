<!--
SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Protobuf API conventions

This directory defines OpenShell's gRPC contracts. These conventions are the
source of truth for public protobuf API design. Apply them to new APIs and when
changing existing APIs; generated SDK naming follows from these definitions.

## Entity references

- Use `name` for the primary resource targeted by an RPC.
- Use the resource's role for a related resource reference, such as `sandbox`,
  `provider`, `service`, or `rule`.
- Do not append `_name` to a canonical entity reference. Its value is already
  the canonical name. Descriptive values that are not entity references, such
  as `display_name`, `file_name`, and `operation_name`, may retain the suffix.
- Public callers reference entities by canonical name. Keep immutable IDs at
  authentication, persistence, compute-driver, and other internal boundaries.

For example:

```proto
message GetSandboxRequest {
  openshell.datamodel.v1.WorkspaceSelector workspace_scope = 2;
  string name = 1;
}

message ExposeServiceRequest {
  openshell.datamodel.v1.WorkspaceSelector workspace_scope = 5;
  string sandbox = 1;
  string name = 2;
}
```

`GetSandboxRequest.name` identifies the RPC's primary resource.
`ExposeServiceRequest.sandbox` identifies a related sandbox while `name`
identifies the service being exposed.

## Workspace scope

- Public workspace-scoped requests declare `workspace_scope` before every
  other field. Existing wire field numbers do not need to follow declaration
  order.
- Type `workspace_scope` as
  `openshell.datamodel.v1.WorkspaceSelector`.
- Requests operating in one workspace require a non-empty canonical
  `WorkspaceSelector.workspace`. The `default` workspace is an explicit name,
  not an omitted-value fallback.
- Accept `WorkspaceSelector.all_workspaces` only on collection-list RPCs that
  explicitly document and authorize cross-workspace access. The supported
  public collections are sandboxes, sandbox templates, providers, and
  services.
- Requests whose primary resource is a workspace use `name`, not
  `workspace_scope`.
- Document every request that permits an omitted selector. Current exceptions
  are platform provider-profile scope and authenticated sandbox bootstrap.

## Field and message design

- Prefer a dedicated request and response message for each RPC, including
  requests that are currently empty.
- Use `google.protobuf.Timestamp` for absolute time and
  `google.protobuf.Duration` for elapsed time.
- Use optional presence when omitted and explicitly empty values have different
  meanings. Do not infer presence from a protobuf scalar's default value.
- Keep public request fields in semantic reading order. Field numbers preserve
  wire identity and may therefore differ from declaration order.
- Document authorization-sensitive selector variants and omission semantics on
  the containing request.

## Schema evolution

- Treat field numbers and fully qualified message names as durable wire
  identities.
- When removing or renaming a field, reserve its old number and source name. Do
  not reuse either for a different meaning.
- Review changes against both the public descriptor closure and durable stored
  protobuf closure described in [the gateway architecture](../architecture/gateway.md#protobuf-api-and-storage-boundaries).
- Regenerate Rust, Python, Go, and TypeScript bindings after contract changes.
  Run `mise run pre-commit`, the affected SDK checks, and relevant server tests
  before submitting the change.

`mise run proto:conventions` checks the mechanical workspace-selector and
legacy entity-reference rules. The guide remains authoritative for semantic
rules that tooling cannot infer, including which resource is primary.
