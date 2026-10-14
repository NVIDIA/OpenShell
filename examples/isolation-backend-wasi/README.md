# Partial Wasmtime isolation backend

This example explores WebAssembly as a different isolation mechanism for the
OpenShell backend contract. It contains a Rust protobuf service and a local
WASIp1 guest runner. It does **not** implement a complete supervisor backend.

The service generates Rust bindings from the repository's public
`SandboxBackend` and `SandboxBoundary` protobuf definitions at build time. It
links no OpenShell implementation crates and lives in its own Cargo workspace.

## Code layout

```text
build.rs           Generate bindings from the public protos
src/main.rs        CLI: serve the backend or run a local guest
src/protocol.rs    Generated bindings, backend name, experimental capability
src/backend.rs     Provisioning, authentication, boundary binding, RPC handlers
src/guest.rs       Wasmtime configuration, WASI capabilities, execution limits
tests/protocol.rs  Subprocess gRPC contract checks
tests/guest.rs     Real guest confinement, resource limits, and interruption
guest.wat          Small WASIp1 filesystem probe
```

## Run the experiment

From the repository root, with Rust 1.94 or newer:

```shell
cargo test --locked --manifest-path examples/isolation-backend-wasi/Cargo.toml
```

The protocol test starts the compiled backend in a separate process and calls it
over loopback gRPC. Guest tests separately check read-only filesystem access,
parent traversal and symlink rejection, fuel and memory limits, bounded output,
unsupported socket imports, and engine interruption. The symlink check requires
Unix. `Cargo.lock` pins dependencies; Wasmtime 46 supports the repository's Rust
version. The first build compiles Wasmtime and Cranelift.

Run a local guest against a directory containing `allowed.txt`:

```shell
cargo run --locked --manifest-path examples/isolation-backend-wasi/Cargo.toml -- \
  run examples/isolation-backend-wasi/guest.wat --workspace /path/to/workspace
```

The bundled filesystem probe also expects `/work/escape` to be a symlink to an
existing file outside the workspace. It asserts that reading that link fails.

Start the partial service with trusted launch coordinates and a credential file
containing at least 32 non-whitespace characters:

```shell
cargo run --locked --manifest-path examples/isolation-backend-wasi/Cargo.toml -- \
  serve examples/isolation-backend-wasi/guest.wat \
  --sandbox-id sandbox-a --session-id session-a --generation-id generation-a \
  --token-file /path/to/protected/credential
```

The service prints JSON containing its ephemeral loopback endpoint, backend name,
and module descriptor. The credential stays in the protected file. Send it as
`authorization: Bearer <credential>` on authenticated RPCs.

The guest is handwritten WebAssembly text in `guest.wat`; no WASI compiler SDK is
needed. File-denial checks trap if an operation unexpectedly succeeds.

The two execution paths are deliberately distinct:

```text
protocol test -> external protobuf service -> reserve a module binding; no execution
local runner -> Wasmtime/WASIp1           -> execute a guest with limited capabilities
```

An `OpenBoundary` call never instantiates the guest. Instantiation can execute a
WebAssembly start function, so it belongs behind an eventual admitted start
operation, not resource binding or confirmation.

## Contract coverage

| Contract area | Prototype behavior | Remaining work |
| --- | --- | --- |
| Backend selection | Own name `example-wasmtime`; descriptor is a provisioned module digest | Generic supervisor setup and trusted driver provisioning |
| Protocol negotiation | Protocol 1.0 with `openshell.example.wasi-prototype` only | Meet the mandatory base contract before advertising `openshell.sandbox.protocol` |
| Authentication | Fixed launch credential loaded from a trusted file; loopback-only service | Production authenticated transport, launch JWT verification, renewal, and supervisor ownership |
| Boundary binding | Exact launch coordinates and descriptor; idempotent reservation | Durable resource ownership, driver deletion, generation replacement, and handle invalidation |
| Attach / confirm / start | `Exchange` validates the route, then returns `UNIMPLEMENTED`; no workload starts | Policy translation, evidence, admission, lifecycle framing, and replay ledger |
| Filesystem confinement | Local runner grants one read-only WASI directory | Translate authored filesystem policy into WASI capabilities |
| Network | Local runner grants no socket-creation capability | Implement guest TCP/DNS host calls and route their decisions and byte streams through the supervisor |
| Workload identity | Runner records SHA-256 of compiled guest bytes | Define guest module path and identity in supervisor policy and audit records |
| Process lifecycle | Local runner captures bounded stdout/stderr, exit codes, traps, and engine interruption | Expose owned guest instances through the supervisor process contract |
| Exec / PTY / signals / forwarding | Unsupported on the wire | Define useful guest semantics or explicit unsupported results |
| Suspend / resume | Authenticated `UNIMPLEMENTED` | Retained-state semantics and old-generation fencing |

The existing base capability is a bundle of mandatory guarantees. A partial
implementation cannot safely advertise that capability just because it implements
the control RPCs. Consequently, a production supervisor's negotiation fails for
this example. The test peer explicitly negotiates the experimental capability.

This is a contract probe, not a route for bypassing supervisor confirmation.
The local `run` command is unreachable through the service and does not install
OpenShell policy, credentials, or mediation.

## What this exposes

WASI guest instances have module identities, not useful host PIDs. The host
Wasmtime executable must not be used as the guest's authorization identity.
The existing executable path/digest shape could represent a module, but the
trusted path mapping and lineage semantics still need a decision.

The mediation contract includes kernel socket cookies, process generations,
syscall timing, and errno-oriented socket decisions. A guest socket host call
does not naturally produce those measurements. A real backend must define
appropriate trusted guest identifiers or prompt a contract change; it must not
fabricate Linux kernel evidence.

Lifecycle support also needs capability decisions. There is no shell, ordinary
fork/exec, PTY, or complete POSIX signal model in this runner. Termination can
interrupt guest execution, but it is not automatically equivalent to every
signal operation.

Finally, `BoundaryErrorKind` currently has no `Unsupported` variant even though
the Rust interface does. This prototype rejects the stream with gRPC
`UNIMPLEMENTED` rather than inventing an inner error value. An admitted partial
backend would need a consistent way to report optional operation support.

## Implementation limits

The runner uses WASIp1 imports supplied by Wasmtime, without inheriting host
environment variables, stdin, or network descriptors. Only `/work` is preopened,
read-only. Guest memory is limited to 16 MiB, tables to 1,024 elements, and each
captured output stream to 64 KiB. Fuel bounds execution; epoch interruption
implements termination for the running WebAssembly guest.

These guest limits do not bound all host resources. Module compilation and host
WASI calls are not governed by instruction fuel, and interruption is not a
general cancellation mechanism for blocking host calls. Production resource
accounting and termination acknowledgement remain open work.

The service is plaintext loopback gRPC with a prototype bearer credential. It
serves one preprovisioned launch and retains state only for its process lifetime.
It does not accept request-controlled module or filesystem paths.

The next integration milestone is an admitted, networkless WASI workload using
attach, confirmation, start, output, wait, and termination through the supervisor.
The following milestone would add a mediated guest socket host function with
authoritative module identity. Neither is implemented here.

Sources: [Wasmtime security model](https://docs.wasmtime.dev/security.html) and
[Wasmtime Rust WASIp1 API](https://docs.rs/wasmtime-wasi/46.0.3/wasmtime_wasi/p1/index.html).
