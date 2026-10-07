# OpenShell supervisor

The supervisor loads and reconciles policy, maintains provider credentials, applies network and MCP inspection, and drives the admitted isolation backend through attachment, confirmation, and workload start.

## Backend startup

The public `run_sandbox` entry point selects the OpenShell Sandbox Protocol backend and collects its startup inputs into a private `SandboxRunConfig`. Shared startup receives that config and the trusted backend setup separately. The `backend_setup` module owns that backend's launch-data decoder, workload policy discovery, and client construction. Descriptor contents cannot select an implementation.

Shared startup checks the admitted backend name before passing the opaque payload to its decoder. It then compares the decoded sandbox, session, and runtime generation with the trusted launch inputs before installing credentials or discovering workload policy. A mismatch stops startup.

The built-in decoder also carries the VM driver's fixed workload identity into shared policy validation. Startup and later policy updates must reject selectors that conflict with that identity. Other launch descriptors do not enable this VM-specific check.

The supervisor admits policy and prepares credentials before constructing and attaching the selected client. It uses the isolation contract's `BoundBoundary` and `ConfirmedBoundary` directly: confirm the attached boundary, prepare network mediation, then start the workload. Backend implementations remain responsible for validating their native enforcement evidence through the isolation contract.

The client receives the supervisor's live provider state, bearer-token slot, and CA-path slot. Provider refresh, token rotation, and later CA publication must remain visible through those shared handles. Startup does not create independent copies of their current values.

The setup interface stays private to the supervisor. It adds no runtime backend registration, endpoint configuration, or public factory API. The public `run_sandbox` signature and standard backend selection remain unchanged.

## OTLP agent trace relay

The `otlp_relay` module forwards the workload's OTLP/HTTP protobuf trace exports to the collector named by `OPENSHELL_OTLP_ENDPOINT`, the same one the supervisor uses for its own spans. The workload exports to the reserved address `192.0.0.8:4318`; the sandbox broker stages that connection to the supervisor, and the network proxy hands the stream to the relay's HTTP/1.1 receiver through the generic reserved-destination hook instead of evaluating policy. The receiver replaces the `openshell.sandbox.id` and `openshell.telemetry.source=agent` resource attributes, pushes the re-encoded batch into a bounded buffer, and a single export task forwards batches over OTLP/gRPC with a lazy connection.

Limits are fixed: 2 MiB per request body, at most 512 `ResourceSpans` entries, 256 KiB of encoded `Resource` fields, and 8192 resource attributes per request (each of these answers 413), a 10 second header-read timeout, 16 concurrent connections, 32 buffered batches, and a 5 second deadline per export attempt. Only the resources are decoded; spans are copied byte for byte, at most two requests at a time. Worst-case memory attributable to the agent is about 67 MiB of buffered batches, plus 32 MiB of bodies awaiting enrichment across the 16 connections, plus about 12 MiB for the two enrichments in progress. A full buffer answers 503 with `Retry-After`. Without a collector endpoint nothing starts and the proxy refuses the relay address. After the agent exits, `run_sandbox_with_backend` flushes buffered batches for up to 5 seconds before it reports the exit to the gateway, then logs a final summary of rejected and failed counts.
