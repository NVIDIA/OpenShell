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
  the canonical name. Descriptive values, local map keys, implementation
  labels, and configured registration names that are not entity references may
  retain the suffix. Examples include `display_name`, `file_name`,
  `driver_name`, `runtime_class_name`, `rule_name`, and `middleware_name`.
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
  protobuf closure. The `public_and_durable_schema_inventories_are_complete`
  test in `openshell-server` owns both inventories.
- Regenerate Rust, Python, Go, and TypeScript bindings after contract changes.
  Run `mise run pre-commit`, the affected SDK checks, and relevant server tests
  before submitting the change.

## Compute-driver application endpoints

`compute_driver.proto` is the internal gateway/driver contract. Ordinary
`GetSandbox` observation does not resolve application routing endpoints.
The optional `ComputeDriverAppEndpoints.ResolveSupervisorAppEndpoint` service
returns the current trusted supervisor listener
and its runtime/ownership binding for advertisement validation. Drivers without
support return `UNIMPLEMENTED`; a successful response with no endpoint means no
safe endpoint is currently available. Neither result authorizes publication.
The gateway owns installation validation and the public discovery API.
The baseline `ComputeDriver` service and generated server trait stay unchanged.

## Supervisor host protocol

[`supervisor_host.proto`](supervisor_host.proto) is the private stream between
a gateway and the supervisor process it shares among its sandboxes: the
supervisor attaches, the gateway sends complete assignment snapshots, and the
supervisor reports what it hosts. It is a version-locked deployment protocol
served on the gateway listener but authorized only for the gateway-minted
supervisor token (`auth_mode: "supervisor"`). It is not imported by
`openshell.proto`, so SDK generation and
gRPC reflection exclude it; the server's schema inventory test classifies it
explicitly. `SandboxInstanceAssignment.launch_material` carries the existing
JSON sandbox instance registration of `openshell-supervisor-control` and is
marked secret.

## Isolation backend protocol

[`isolation_backend.proto`](isolation_backend.proto) defines backend discovery,
boundary binding, and optional suspend/resume RPCs.
[`sandbox_protocol.proto`](sandbox_protocol.proto) defines typed workload
control, process I/O, and network mediation over the bound boundary. Both are
supervisor-to-backend contracts, not gateway RPCs. Backend authors can generate bindings independently
from these definitions. The negotiated Sandbox Protocol version covers the gRPC
services, typed messages, streaming, and lifecycle semantics.

## Driver contract documents

[`sandbox_runtime.proto`](sandbox_runtime.proto) specifies the documents a
compute driver receives from the gateway or hands to the supervisor and the
sandbox boundary, besides the `ComputeDriver` service: the launch
authentication, the supervisor auth bundle, the runtime descriptor, and the
boundary configuration. They travel as files or as opaque `bytes`, never as gRPC
messages, and are the canonical protobuf JSON of their messages. A writer emits
the canonical form; a reader accepts the original field names too and rejects
unknown fields. The messages reuse `ResolvedWorkloadIdentity` and
`DriverFenceEvidence` from `compute_driver.proto` instead of redefining them.

The launch authentication and the supervisor auth bundle it carries are defined
in [`launch_credentials.proto`](launch_credentials.proto), in package
`openshell.compute.v1`. They cannot sit in `sandbox_runtime.proto`'s package:
`compute_driver.proto` carries the launch authentication as a typed message, and
`sandbox_runtime.proto` imports `compute_driver.proto`, so a shared package
would create an import cycle, which `buf` rejects. `DriverSandboxSpec` and
`StartSandboxRequest` carry it as `launch_credentials` beside the older
opaque `launch_authentication` bytes (the serde JSON of the legacy type). The
gateway fills both. A driver uses the typed field when it is set and otherwise
decodes the bytes, so an older gateway and a newer driver, and the reverse, keep
working. Remove the bytes once no supported gateway or driver relies on them.

These messages replace the legacy documents that the Rust types in
`openshell-driver-sdk` (`legacy_contract`) write today. A document in the new
encoding carries `contract_version`, which a legacy document does not, so a
reader can tell the two apart. `openshell-driver-sdk` converts between the two
and its tests pin the protobuf JSON examples. The file is not imported by
`openshell.proto`, so the SDKs do not generate it.

During the transition a driver writes each document in the new encoding beside
its legacy file, in a file named like the legacy one with `.pb.json` in place of
`.json` (`bootstrap.json` and `bootstrap.pb.json`). A reader looks for the new
file first and falls back to the legacy one. A new file that exists but is
invalid is an error, not a reason to fall back. A single-use document, such as
the boundary configuration, is removed in both forms once it has been read.
An older driver writes only the legacy file and an older reader ignores the new
one, so each side can be upgraded independently. A driver must not be replaced
by an older one while it leaves new files behind: the newer readers would prefer
the stale files.
