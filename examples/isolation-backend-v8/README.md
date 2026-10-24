# js-sbx

A small JavaScript runtime controlled by the OpenShell supervisor through the
Sandbox Protocol. `js-sbx` runs natively on the host and executes the guest in
a V8 isolate. It exposes `console.log`, `console.error`, and a `fetch` stub that
throws `Network access is disabled`. The guest has no filesystem, subprocess,
socket, or module-loading bindings.

```text
gateway -> example driver -> supervisor -> Unix socket -> js-sbx -> V8 isolate
```

## Start

From this example directory, as a non-root user:

```shell
./start.sh
```

The script builds the binaries and starts the runtime, example driver, and
gateway. It generates the local configuration and launch credentials; no manual
certificate setup is needed. The first build downloads V8. To use another script,
run `./start.sh path/to/script.js`.

The gateway listens without user authentication on `127.0.0.1:18770`.
Supervisor-to-runtime RPCs use an authenticated Unix socket. The script prints
the temporary directory containing configuration and logs.

## Gateway configuration

These are the driver and backend sections of the generated `gateway.toml`.
`<state-dir>` is the temporary directory printed by the script; listener,
authentication, and signing-key settings are omitted here.

```toml
[openshell.gateway]
compute_driver = "js-sbx-example"

[openshell.drivers.js-sbx-example]
socket_path = "<state-dir>/compute.sock"
isolation_backend = "js-sbx"

[[openshell.supervisor.isolation_backends]]
name = "js-sbx"
endpoint = { kind = "unix", socket_path = "<state-dir>/backend.sock" }
```

`start.sh` runs the same binary in two processes: `js-sbx driver` provisions the
supervisor and launch metadata; `js-sbx serve` implements `IsolationBackend` and
`SandboxProtocol`. The runtime starts JavaScript only after Attach, Confirm,
and StartAgent. The existing example directory name refers to the V8 engine.

## Create a sandbox

In another terminal, from this example directory:

```shell
export OPENSHELL_GATEWAY_ENDPOINT=http://127.0.0.1:18770
openshell sandbox create --name js-demo \
  --keep --no-tty --no-auto-providers -- /work/guest.js
```

The bundled script prints a greeting, attempts a request, catches the
network-disabled error, and counts once per second for about 12 seconds.
Egress is disabled by the runtime's lack of network bindings; this example
does not relay requests to the supervisor for policy evaluation. No policy
file is needed.

The create command prints the script's output and returns its exit code. The
sandbox becomes `Completed` on exit code 0 or `Error` on a nonzero exit code.
Uncaught exceptions and Promise rejections left unhandled after microtasks finish
print an error and return exit code 1.
`--keep` retains the sandbox so you can inspect that result after the command.

Add `--detach` to run without attaching; detached creation does not stream guest
output. Use `openshell sandbox connect js-demo` to attach afterward.

## Suspend and resume

Suspension freezes the V8 isolate in place and the `js-sbx serve` process keeps
it in memory; resume continues the same isolate in a new runtime generation.
The default `guest.js` counts for about 12 seconds after its network check:

```shell
./start.sh
```

In another terminal, create the sandbox, then suspend and resume it while it
counts:

```shell
openshell sandbox create --name js-demo \
  --keep --no-tty --no-auto-providers --detach -- /work/guest.js
openshell sandbox suspend js-demo
openshell sandbox resume js-demo
```

To discard the retained state and start the script from the beginning:

```shell
openshell sandbox stop js-demo
openshell sandbox start js-demo
```

`backend.log` shows the count continue from its value at suspension, and the
elapsed time includes the gap. The 15-second deadline counts only running time.

The driver sends `SIGUSR1` to the supervisor, which calls `SuspendBoundary`.
The backend retains the frozen isolate and privately persists its handle in
`restore-reference` before acknowledging suspension. The supervisor exits;
it does not write or read a reference file. On resume the driver provisions
the backend using `launch.json`, while the supervisor attaches through its
ordinary boundary-opening path. The shared `boundary.json` contains no
retention fields. The reference authenticates the sandbox with a key in
`retention.key`, so a restarted `js-sbx serve` can tell lost state from a forged
or superseded reference. If you restart `js-sbx serve` while the sandbox is suspended, resume
fails and the sandbox stays `Suspended`; `openshell sandbox start js-demo`
then runs the script from the beginning.
`openshell sandbox start`, `stop`, and `delete` discard the retained state.

Restoration borrows the retained guest until the driver observes supervisor
readiness and consumes `restore-reference`. If startup fails or times out,
the driver stops the supervisor and waits for the backend to refreeze the guest
before reporting failure. The same reference remains available for a retry.

## Inspect and stop

```shell
openshell sandbox list
openshell logs js-demo
openshell sandbox delete js-demo
```

Wait for deletion, then press Ctrl-C in the script's terminal to stop all three
processes. Each run uses a fresh state directory and keeps its logs.

## Limits

One script runs at a time, with a 15-second deadline, a 32 MiB JavaScript heap
limit, and 64 KiB per output stream. Termination interrupts the isolate. These
limits do not bound all native V8 resources. The V8 isolate confines JavaScript;
the host process does not run in a Linux namespace or container.

The example has no HTTP relay or guest network implementation. `fetch` is only
a synchronous denial stub. Exec, PTY, providers, and supervisor recovery are
unsupported. Retained state lives only in the `js-sbx serve` process memory.
