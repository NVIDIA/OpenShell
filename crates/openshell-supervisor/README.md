# OpenShell supervisor

The supervisor loads and reconciles policy, maintains provider credentials, applies network and MCP inspection, and drives the admitted isolation backend through attachment, confirmation, and workload start.

## Backend startup

The public `run_sandbox` entry point selects the OpenShell Sandbox Protocol backend and collects its startup inputs into a private `SandboxRunConfig`. Shared startup receives that config and the trusted backend setup separately. The `backend_setup` module owns that backend's launch-data decoder, workload policy discovery, and client construction. Descriptor contents cannot select an implementation.

Shared startup checks the admitted backend name before passing the opaque payload to its decoder. It then compares the decoded sandbox, session, and runtime generation with the trusted launch inputs before installing credentials or discovering workload policy. A mismatch stops startup.

The built-in decoder also carries the VM driver's fixed workload identity into shared policy validation. Startup and later policy updates must reject selectors that conflict with that identity. Other launch descriptors do not enable this VM-specific check.

The supervisor admits policy and prepares credentials before constructing and attaching the selected client. It uses the isolation contract's `BoundBoundary` and `ConfirmedBoundary` directly: confirm the attached boundary, prepare network mediation, then start the workload. Backend implementations remain responsible for validating their native enforcement evidence through the isolation contract.

The client receives the supervisor's live provider state, bearer-token slot, and CA-path slot. Provider refresh, token rotation, and later CA publication must remain visible through those shared handles. Startup does not create independent copies of their current values.

The setup interface stays private to the supervisor. It adds no runtime backend registration, endpoint configuration, or public factory API. The public `run_sandbox` signature and standard backend selection remain unchanged.

## Console logging

Diagnostics and OCSF shorthand share a bounded, nonblocking stderr writer. With `ocsf_json_enabled=true`, the same writer also receives timestamped `OCSF-JSON` records. Each formatter submits a complete line in one write so concurrent producers cannot interleave records in the queue. The 1,024-line queue drops new lines when full rather than waiting for stderr.

Console JSON is installed independently of optional file appenders and uses an INFO filter independent of the diagnostic filter. Its runtime enabled flag and target schema version are shared with the existing JSONL file layer. The supervisor retains the writer guards until shutdown. The gateway log push layer continues to emit shorthand only.

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
