# OpenShell supervisor

The supervisor loads and reconciles policy, maintains provider credentials, applies network and MCP inspection, and drives the admitted isolation backend through attachment, confirmation, and workload start.

## Backend startup

The public `run_sandbox` entry point selects the OpenShell Sandbox Protocol backend and collects its startup inputs into a private `SandboxRunConfig`. Shared startup receives that config and the trusted backend setup separately. The `backend_setup` module owns that backend's launch-data decoder, workload policy discovery, and client construction. Descriptor contents cannot select an implementation.

Shared startup checks the admitted backend name before passing the opaque payload to its decoder. It then compares the decoded sandbox, session, and runtime generation with the trusted launch inputs before installing credentials or discovering workload policy. A mismatch stops startup.

The built-in decoder also carries the VM driver's fixed workload identity into shared policy validation. Startup and later policy updates must reject selectors that conflict with that identity. Other launch descriptors do not enable this VM-specific check.

The supervisor admits policy and prepares credentials before constructing and attaching the selected client. It uses the isolation contract's `BoundBoundary` and `ConfirmedBoundary` directly: confirm the attached boundary, prepare network mediation, then start the workload. Backend implementations remain responsible for validating their native enforcement evidence through the isolation contract.

The client receives the supervisor's live provider state, bearer-token slot, and CA-path slot. Provider refresh, token rotation, and later CA publication must remain visible through those shared handles. Startup does not create independent copies of their current values.

The setup interface stays private to the supervisor. It adds no runtime backend registration, endpoint configuration, or public factory API. The public `run_sandbox` signature and standard backend selection remain unchanged.

The private startup result separates the backend transport payload from optional
authenticated CONNECT listener settings. Shared networking starts the listener
only after boundary attachment and confirmation; the supervisor owns policy
evaluation, live credentials, and listener lifetime. These settings do not add
a proxy hook to the isolation interface or the shared Sandbox Protocol descriptor.

## Console logging

Diagnostics and OCSF shorthand share a bounded, nonblocking stderr writer. With `ocsf_json_enabled=true`, the same writer also receives timestamped `OCSF-JSON` records. Each formatter submits a complete line in one write so concurrent producers cannot interleave records in the queue. The 1,024-line queue drops new lines when full rather than waiting for stderr.

Console JSON is installed independently of optional file appenders and uses an INFO filter independent of the diagnostic filter. Its runtime enabled flag and target schema version are shared with the existing JSONL file layer. The supervisor retains the writer guards until shutdown. The gateway log push layer continues to emit shorthand only.

## OTLP agent trace relay

The `otlp_relay` module forwards the workload's OTLP/HTTP protobuf trace exports to the collector named by `OPENSHELL_OTLP_ENDPOINT`, the same one the supervisor uses for its own spans. The workload exports to the reserved address `192.0.0.8:4318`; the sandbox broker stages that connection to the supervisor, and the network proxy hands the stream to the relay's HTTP/1.1 receiver through the generic reserved-destination hook instead of evaluating policy. The receiver replaces the `openshell.sandbox.id` and `openshell.telemetry.source=agent` resource attributes, pushes the re-encoded batch into a bounded buffer, and a single export task forwards batches over OTLP/gRPC with a lazy connection.

Limits are fixed: 2 MiB per request body, at most 512 `ResourceSpans` entries, 256 KiB of encoded `Resource` fields, and 8192 resource attributes per request (each of these answers 413), a 10 second header-read timeout, 16 concurrent connections, 32 buffered batches, and a 5 second deadline per export attempt. Only the resources are decoded; spans are copied byte for byte, at most two requests at a time. Worst-case memory attributable to the agent is about 67 MiB of buffered batches, plus 32 MiB of bodies awaiting enrichment across the 16 connections, plus about 12 MiB for the two enrichments in progress, plus about 4 MiB for the batch being exported and its encoded copy. A full buffer answers 503 with `Retry-After`. Without a collector endpoint nothing starts and the proxy refuses the relay address. After the agent exits, `run_sandbox_with_backend` flushes buffered batches for up to 5 seconds before it reports the exit to the gateway, then logs a final summary of rejected and failed counts. Flushes skip the wait while the most recent export failed, and batches still pending when the relay is dropped without a flush count as failed. The supervisor tells the sandbox runtime through `AgentSpec::otlp_relay_active` whether the relay runs, and the runtime injects the generic `OTEL_EXPORTER_OTLP_*` defaults only then.

## Safe runtime and parent liveness

The supervisor drives the safe isolation-backend contract and network/policy
orchestration. Its library and executable forbid unsafe code.

For a VM host supervisor, the VM driver passes its parent-liveness pipe as stdin
and sets the private `--parent-liveness-stdin` flag. A dedicated reader terminates
the supervisor when the driver closes its write endpoint or exits. The driver
protects both original pipe endpoints with close-on-exec and lets `Stdio` transfer
the read endpoint to the child's stdin. The supervisor uses the standard stdin
reader and does not adopt a numeric raw descriptor. This mode reserves stdin for
liveness; sandbox workload input travels over the boundary protocol.

## Portable supervisor access

The supervisor consumes the shared isolation backend contract. Its gateway
session, canonical process attachment, and TCP readiness do not require SSH or
a Unix host.

TCP readiness opens only after the gateway accepts the authenticated session.
Session loss closes readiness; accepted reconnection restores it. Dropping the
readiness guard closes the listener. A requested Unix readiness endpoint fails
explicitly on unsupported hosts, even before session acceptance.

The optional Unix SSH adapter remains separate from boundary-based process I/O.
The process-access multiplexer consumes boundary-provided streams and delegates
terminal resizing and signals through the existing isolation contract. It does
not own local PIDs, PTYs, or process-group signaling; native process operations
belong to the sandbox or isolation backend. Signals use `BoundarySignal`.

These portable control-plane foundations do not qualify a platform isolation
backend or enable a Windows workload runtime.
