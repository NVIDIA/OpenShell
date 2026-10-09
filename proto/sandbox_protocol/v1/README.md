<!--
SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# OpenShell Sandbox Protocol 1.0

This is the wire contract for an isolation backend implemented outside the
OpenShell tree. An implementation may use any language and owns its native
isolation mechanisms. Generate gRPC bindings from
[`isolation_backend.proto`](../../isolation_backend.proto),
[`sandbox_protocol.proto`](../../sandbox_protocol.proto), and their imports.
No OpenShell guest executable or linked backend implementation is required.

The negotiated isolation version covers **both** the control RPCs and the
framing and JSON messages below. Version 1.0 requires
`openshell.isolation.contract` on both peers. An incompatible change to a
message, framing, authentication, or lifecycle guarantee requires a major bump.
A minor revision may add optional capabilities; it must preserve all 1.0
messages and behavior. A new operation requires an advertised capability
before a sender uses it. Adding fields to an existing 1.0 request requires a
major bump: additional request fields are not part of 1.0 and must not be sent.
Unknown required capabilities fail startup. This
contract is independently versioned from OpenShell releases.

## Trusted registration and launch

The gateway reads `isolation_backend` from the selected compute driver's
`[openshell.drivers.<name>]` table and resolves it through
`openshell.supervisor.isolation_backends` in operator-owned `gateway.toml`.
Selecting `openshell.gateway.compute_driver` selects both the driver and its
backend; their names can differ.
It sends the resolved `IsolationBackendRegistration` through the compute
protocol in validation/create specs and every start request, including recovery.
This requires the driver's `openshell.compute.isolation-backend-registration`
capability; unsupported drivers fail gateway startup. Missing selection or
`openshell-sandbox` retains the built-in runtime. The public sandbox spec has
no selector or endpoint.

The driver must reject any registered backend it cannot place, before creating
workload resources. It converts the typed endpoint to the JSON registration
below and supplies the exact admitted name. Rust drivers can use
`openshell_core::isolation_registration::BackendRegistration::try_from` and
serialize the result in a `{"backends":[...]}` wrapper. This compute launch
handoff does not change the supervisor-to-backend Protocol 1.0 contract.
The gateway pins the admitted backend name in internal sandbox metadata and
rejects start/recovery under a different selection. Legacy records without
that binding retain `openshell-sandbox`. Endpoint addresses are not persisted.

These files and flags are supervisor CLI inputs versioned with the supervisor
release, independently of the negotiated wire protocol. Both file formats
reject unknown fields.

The operator supplies `--isolation-backends-file` to `openshell-supervisor`:

```json
{
  "backends": [
    {
      "name": "agent-substrate",
      "endpoint": {
        "kind": "unix",
        "socket_path": "/run/agent-substrate/isolation.sock"
      }
    }
  ]
}
```

TCP endpoints use `{"kind":"tcp","authority":"backend.example:443",
"addresses":["192.0.2.10:443"]}`. Addresses are operator-pinned concrete socket
addresses; the supervisor does not resolve workload-provided hostnames.
Vsock endpoints use `{"kind":"vsock","guest_cid":3,"port":47000}`.
Vsock connects to a guest CID of at least 3; wildcard CIDs and ports are invalid.
Registration names contain 1–128 ASCII letters, digits, `-`, `_`, or `.`, and
match exactly. Duplicate names, malformed endpoints, unknown
names, and replacement of `openshell-sandbox` fail startup.

The trusted compute driver or orchestrator supplies:

- `OPENSHELL_ADMITTED_ISOLATION_BACKEND`: the independently admitted backend
  name, never copied from sandbox environment or request input.
- `--backend-descriptor-file`: the driver's opaque native bytes. The supervisor
  passes them unchanged as `OpenBoundaryRequest.driver_descriptor`.
- `--boundary-launch-file`: JSON with `backend_name`, `sandbox_id`, `generation`, `session_id`,
  `workload_identity`, `tls`, `resource_claims`, `outer_fence`, and optional
  `host_gateway_ip`. These are trusted launch coordinates, separate from the
  native descriptor. Its backend name must match the admitted name. No endpoint
  is accepted in this file.
- `--auth-bundle-file`: the existing gateway-issued `SupervisorAuthBundle`.

`tls` contains `server_name` and `trust_anchor_pem`. The driver pins the serving
identity for this generation, including for Unix sockets and vsock. Both TLS
fields must be nonempty, and the trust anchor must parse as certificates. TCP
`authority` controls HTTP routing; `tls.server_name` controls SNI and certificate
verification. The backend derives launch identity, claims and fence from its
native descriptor or trusted driver state; it must independently verify them
before returning confirmation.

Both JSON files and native descriptor bytes are protected from workload writes.
The
registration file belongs to the operator and must be delivered outside
workload mounts. In-tree drivers continue to select `openshell-sandbox`; an
external compute driver stages the files and launches the stock supervisor.
The public sandbox API has no endpoint or isolation-backend selector.

## Authentication and ordering

TLS 1.3 verifies the generation-pinned serving certificate and negotiates HTTP/2
with ALPN `h2`. Every control RPC except `GetCapabilities`, and every stream,
uses `authorization: Bearer <sandbox-token>`. The backend validates the token's
signature with the trusted gateway verification keys and its expiry, audience,
gateway ID, sandbox ID, runtime generation, and authorization epoch.
TLS authenticates the backend; the bearer authenticates the supervisor.

The JWT header uses `alg: "EdDSA"`, an operator-provisioned `kid`, and
`typ: "openshell-sandbox-session+jwt"`. Required claims are:
`iss: "openshell-gateway:<gateway ID>"`,
`sub: "spiffe://openshell/sandbox/<sandbox ID>"`, `aud: "openshell-sandbox"`,
`iat: i64`, `exp: i64`, `jti: UUID`, `sandbox_id: string`,
`runtime_generation: string`, `auth_epoch: nonzero u64`, and
`component: "openshell-supervisor"`. Verify Ed25519 signatures against trusted
keys; never select a key or issuer supplied by the workload. Reject unknown
claims, wrong component/type/audience/issuer/subject, or a different sandbox,
generation, or admitted authorization epoch. Allow at most 30 seconds of clock
skew. For exp != 0, require iat < exp, a lifetime at most one hour, and an
unexpired token (with that skew). exp == 0 is the gateway's configured
nonexpiring profile; accept it only when the operator enables that profile on
the backend. Launch session binding is checked by OpenBoundary and
confirmation; it is not a JWT claim.

The logical supervisor instance UUID is separate from the launch session.
Attach pins it for the generation. Reject another instance, and never replace
an active connection with another of the same epoch until the old connection
has closed. Confirmation promotes a staged authenticated connection. Retain
these ownership rules across transport recovery and credential renewal.

On **each physical connection**, negotiate `PeerMetadata`, call authenticated
`OpenBoundary`, then use its nonempty opaque handle as the first client frame
on every `Exchange` or `Mediate` stream. Handles are at most 128 UTF-8 bytes.
Each control RPC message fits within 64 KiB of encoded protobuf, including the
opaque driver descriptor and launch coordinates in `OpenBoundary`.
After validating the binding, the server sends initial gRPC metadata before
waiting for the JSON request. The client waits for that metadata to complete
stream opening; delaying it until a response payload causes a deadlock.
All subsequent client frames and all response frames contain `data`. Empty data
is allowed; it never binds a stream. Protobuf message boundaries have no meaning
inside the concatenated data bytes. A handle without authentication or without
opening on the current connection has no authority.

Opening only validates/reserves a route. Image policy discovery is read-only.
`attach` binds the admitted context; `confirm` establishes enforcement;
`start_agent` is the only operation that makes the admitted agent runnable.
No untrusted instruction may execute before those checks complete. Exec and
forwarding require `Running`. Reject out-of-order operations without advancing
state. Only the same logical supervisor may recover its transport in the same
generation. A replacement supervisor needs a newly authorized launch.

A backend must validate native enforcement evidence before issuing confirmation.
The shared client verifies common properties and their immutable launch binding;
it does not interpret an external backend's `backend_audit`. The built-in backend
continues to validate Linux-specific evidence. An external backend remains
responsible for the RFC 0012 lifecycle and failure invariants, including bounded
termination when required enforcement disappears. Backend selection is a trust
boundary, not a mechanism for accepting untrusted attestations.

## Control framing and replay

Each logical stream begins with one request and its matching response:

```text
u32 big-endian UTF-8 JSON length | JSON bytes
```

The maximum JSON payload is 1,048,576 bytes. Integers use their complete wire
range; avoid conversion through floating-point numbers. Byte arrays in JSON
are arrays of integers in 0..255, not base64. Paths, IP addresses, socket
addresses, UUIDs, and SHA-256 digests are strings. Socket addresses use
`IPv4:port` or `[IPv6]:port`. Digests are 64 lowercase hex characters.
Optional values are JSON `null` unless explicitly omitted below. Map keys are
strings. Fields are required unless described as optional or defaulted.

Request envelope:

```json
{
  "request_id": "00000000-0000-4000-8000-000000000001",
  "payload_digest": "<SHA-256 described below>",
  "request": { "operation": "discover_policy" }
}
```

`request_id` is a cryptographically random UUID scoped to the runtime generation.
`exec_expires_at_unix_ms` is omitted for non-exec requests; exec requires an
absolute admission deadline, normally 30 seconds after request creation.
Host and backend wall clocks must be synchronized; exec deadlines have no skew
allowance. The deadline limits exec
admission/recovery, not the lifetime of an admitted process.

The sender emits all request fields, including nulls and defaults. To compute
`payload_digest`, canonicalize the `request` object as transmitted, without
dropping or inventing fields. For exec, add `exec_expires_at_unix_ms` to a copy
of that object for hashing only. Recursively sort object keys by UTF-8 byte
order (equivalently, Unicode code point order). Serialize compact UTF-8 JSON
without whitespace. Escape quote, backslash, backspace, form feed, newline,
carriage return and tab as `\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`;
escape other control characters below U+0020 as lowercase `\u00xx`. Do not
escape non-ASCII characters or `/`. Integers use base-10 digits without leading
zeros; floating point values are not used. Hash these bytes with SHA-256.
Object order in the transmitted message is immaterial. See
[`vectors.json`](vectors.json) for independently generated request byte/digest examples
checked by Rust and the independent Python fixture. Frame hex provides one
valid serialization; its object key order is not normative.

The backend validates the digest and records replayable mutations by generation
and request ID. The same ID and digest returns the original result without
repeating effects; the same ID with a different digest fails. Replayable requests
are attach, confirm, start_agent, update_provider_environment, exec, signal,
terminate, terminate_boundary, exec_signal, and resize. Non-exec mutation results
remain replayable for the generation. Exec IDs remain admitted until their
absolute deadline, independently of process/output retention. Expired execs fail
even if their ID was discarded. An unknown outcome after transport loss does
not authorize launching another exec under a new ID.

Responses use `{"request_id":"<same ID>","response":{"result":"..."}}`.
The result may be followed by stream data as specified below. Structured errors
use `{"result":"error","kind":"invalid|denied|unavailable|terminated|process",
"message":"..."}` and must not include secrets.

## Request and response messages

`operation` selects the request; `result` selects the response. Fields listed
below belong to that object alongside its tag. Empty field lists mean the tag
alone. IDs are opaque generation-scoped strings, never local process IDs.

| Operation | Request fields | Success result and fields |
|---|---|---|
| `discover_policy` | — | `image_policy`: `yaml: string\|null`, `invalid: bool` |
| `attach` | `supervisor_instance_id: UUID`, `policy: Policy`, `resource_claims: map<string,string>` | `attached`: `snapshot: SessionSnapshot` |
| `confirm` | — | `confirmed`: `confirmation: Confirmation` |
| `probe_provider_files` | — | `provider_files_supported` |
| `start_agent` | `sandbox_id: string`, `spec: AgentSpec`, `policy: Policy`, `ca_cert: string\|null`, `ca_bundle: string\|null`, `provider_env_revision: u64`, `provider_env: map<string,string>`, `provider_files: map<string,string>` (default `{}`) | `started`: `process_id: string`, `provider_env_revision: u64`, `provider_env_generation: u64` |
| `update_provider_environment` | `generation: u64`, `revision: u64`, `provider_env: map<string,string>`, `provider_files: map<string,string>` (default `{}`) | `provider_environment_updated`: `revision: u64`, `generation: u64`, `applied: bool` |
| `attach_process` | `process_id: string` | `process_attached`: `terminal: bool`; then process I/O |
| `wait` | `process_id: string` | `exited`: `status: ExitStatus` |
| `signal` | `process_id: string`, `signal: Signal` | `signaled` |
| `terminate` | `process_id: string` | `terminated` |
| `terminate_boundary` | — | `boundary_terminated` |
| `exec` | `spec: ExecSpec` | `exec_started`: `process_id: string`, `pty: bool`; then process I/O |
| `exec_signal` | `process_id: string`, `signal: Signal` | `signaled` |
| `resize` | `process_id: string`, `cols: u16`, `rows: u16` | `resized` |
| `loopback_connect` | `host: IP string`, `port: u16` | `port_connected`; then raw bidirectional bytes |
| `accept_network` | — | `network_connected`: `identity: BinaryIdentity`, `destination: socket address`, `socket: SocketMetadata`, `policy_generation: u64`, `timing: Timing`; then TCP decision/relay |
| `open_mediation` | —; sent on `Mediate` | `mediation_ready`; then persistent DNS framing |

Image policy parse/read failure returns `invalid: true` or an error; it must
never be represented as missing policy. `attach` includes policy with the
supervisor's ready mediation listener. Replayed attach returns the owned session
snapshot without transferring ownership to another supervisor instance.
Termination acknowledgments require all targeted owned processes to be terminal.
`wait` returns a stable status, including on repeat calls.

Before sending provider files, the supervisor probes support. Provider snapshots
replace the previous environment/files atomically. `generation` orders
publications within a session; stale publications must not replace newer ones.
`applied` is true for an installed publication or its exact replay. Existing
process environments remain unchanged; subsequent execs observe the installed
snapshot. Workload launch applies all controls before its first instruction.

### Compound JSON types

- **AgentSpec**: `program: string`, `args: string[]`, `workdir: string|null`,
  `timeout_secs: u64`, `interactive: bool`. An empty program asks the backend to
  resolve the image's default login shell.
- **ExecSpec**: `program: string`, `args: string[]`, `env: [string,string][]`,
  `workdir: string|null`, `pty: bool`, `shell: ShellSpec|null` (default `null`),
  `runtime_helper: "sftp"|null` (default `null`).
- **ShellSpec**: `command: string|null`, `login: bool`. The backend resolves the shell
  against the workload image. Shell and runtime helper are mutually exclusive.
- **Policy**: `version: u32`, `read_only: string[]`, `read_write: string[]`,
  `include_workdir: bool`, `network: "block"|"proxy"|"allow"`,
  `proxy_addr: socket address|null`, `landlock: "best_effort"|"hard_requirement"`,
  `run_as_user: string|null`, `run_as_group: string|null`. These wire names remain
  historical; the external backend translates admitted constraints into its own
  mechanisms and fails when it cannot enforce them.
- **Identity**: `uid: u32`, `gid: u32`, `supplementary_gids: u32[]`,
  `source: string`, `resource_digest: string`. UID, GID, and groups are nonzero;
  groups are sorted, unique, and exclude the primary GID. Source and resource
  digest are nonempty driver-owned values.
- **Property**: `enforced: bool`, `mechanism: string`. Confirmation requires
  `enforced: true` and a nonempty mechanism for each property.
- **Properties**: `filesystem_confinement: Property`, `egress_interception:
  Property`, `request_attribution: Property`, `privilege_floor: Property`.
- **OuterFence**: `generation: string`, `established: string[]`,
  `evidence_digest: SHA-256 string`. Established guarantees are exactly
  `default_deny_egress`, `no_unmanaged_egress_path`, `revocation_verified`, and
  `controller_loss_fails_closed`. The digest commits to
  `u64be(UTF-8 generation length) || generation || validated native evidence`.
  Serialize the guarantee array in the listed order. The enforcement owner
  validates native evidence before projecting these guarantees.
- **Confirmation**: `generation: string`, `identity: Identity`, `properties:
  Properties`, `authenticated_supervisor: bool`, `session_id: UUID`,
  `outer_fence: OuterFence`, `runtime_exit_terminates_workload: bool`,
  `resource_claims: map<string,string>`, `backend_audit: any JSON`. Generation,
  session, identity, claims, and fence must match trusted launch metadata;
  both booleans must be true. The backend owns validation of its audit payload.
- **SessionSnapshot**: `generation: string`, `processes: ProcessSnapshot[]`.
- **ProcessSnapshot**: `process_id: string`, `kind: "main"|"exec"`, `terminal:
  bool`, `status: ExitStatus|null`, `retained_output: OutputWindow`.
- **OutputWindow**: `first_sequence: u64`, `next_sequence: u64`, `truncated: bool`.
- **ExitStatus**: `{"kind":"exited","value":i32}` or
  `{"kind":"signaled","value":i32}`.
- **Signal**: `"term"`, `"kill"`, `"int"`, or `"hup"`.
- **ExecutableIdentity**: `path: string`, `digest: SHA-256 string|null`.
- **BinaryIdentity**: `{"result":"resolved","executable":ExecutableIdentity,
  "ancestors":ExecutableIdentity[],"cmdline_paths":string[]}` or
  `{"result":"failed","message":string}`. Identity must come from trusted
  backend observation; never substitute workload claims on resolution failure.
- **SocketMetadata**: `socket_cookie: u64`, `nonblocking: bool`,
  `process_generation: u64`.
- **Timing**: `notification_to_queue_us: u64`, `queue_wait_us: u64`.

## Process I/O, TCP relay, and DNS

Process I/O uses `u8 channel | u32be payload length | payload`, with a maximum
payload of 65,536 bytes:

| Channel | Direction | Meaning |
|---|---|---|
| 0 | supervisor → backend | stdin bytes |
| 1 | backend → supervisor | stdout bytes |
| 2 | backend → supervisor | stderr bytes (non-PTY only) |
| 3 | backend → supervisor | UTF-8 JSON ExitStatus |
| 4 | supervisor → backend | stdin closed; empty payload |
| 5 | supervisor → backend | UTF-8 JSON TCP decision |

PTY sessions merge stderr into stdout. Send exit only after output drains;
closing stdin must not close the response direction. Relay and exec streams
must not starve control or DNS traffic. The reference transport supports 128
concurrent streams, 256 KiB per-stream windows, and a 48 MiB connection window.

After `network_connected`, the backend waits for channel 5. The JSON decision is
`"RelayReady"` or `{"Denied":"PolicyDenied|IdentityUnavailable|
InvalidDestination|ResourceExhausted|MediationUnavailable"}` (one exact enum
value, without `|`). Denial leaves the socket uncommitted; mediation loss denies
by default. `RelayReady` switches to raw bidirectional bytes, and does not bypass
subsequent L7 policy. Each TCP open owns an independent `Exchange` stream.

After `mediation_ready`, DNS uses `u8 kind | u64be stream ID | u32be JSON length |
JSON`, with a maximum JSON payload of 262,144 bytes. Kind 5 carries a backend
query: `request: byte[]`, `transport: "Udp"|"Tcp"`, `identity: BinaryIdentity`,
`timing: Timing`. Kind 6 carries the matching supervisor result:
`{"result":"response","value":byte[]}` or
`{"result":"error","value":string}`. Stream IDs correlate independent queries
on the persistent channel. Malformed framing, unknown kinds, lost mediation, or
queue exhaustion fail closed; they never authorize direct DNS/egress.

## Conformance and optional retention

An external backend must exercise descriptor rejection, lifecycle ordering,
confirmation mismatch, exec replay/deadlines, provider publication, forwarding,
TCP/DNS decisions, connection recovery, credential rotation, and enforcement
loss in its actual driver placement. OpenShell's delegated adapter tests verify
opaque payload forwarding and generic evidence without a native Linux audit.
Its existing transport suites cover recovery, credential renewal, and flow
control; Docker lifecycle E2E verifies the built-in placement. Run
`mise run e2e:isolation-protocol` for the stock supervisor against an independent
Python implementation generated from the public protos. That fixture tests
interoperability and launch ordering, and simulates enforcement evidence with a
fixed test bearer. It does not exercise JWT validation or provide isolation.

Suspend/resume is a separate optional capability described in
`isolation_backend.proto`. Protocol 1.0 implementations may return
`UNIMPLEMENTED` without advertising it. This registration path supports fresh
launches; it does not yet orchestrate state-preserving restoration.
