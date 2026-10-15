# Local V8 sandbox backend

Run a JavaScript file in a V8 isolate and see the supervisor deny its HTTP
request. The driver and backend run as separate processes. Use a non-root
account with the repository's Rust build prerequisites installed.

## Start

From this example directory:

```shell
./start.sh
```

Pass a JavaScript file to run another script: `./start.sh path/to/script.js`.

The script builds the binaries, generates local configuration and credentials,
and starts the backend, driver, and gateway. The first build downloads the V8
library. The script prints the temporary directory containing `gateway.toml` and
logs. The gateway accepts unauthenticated requests on `127.0.0.1:18770`; the
backend uses an authenticated Unix socket.

## Gateway configuration

These are the driver and backend sections of the generated `gateway.toml`.
`<state-dir>` is the temporary directory printed by the script; listener,
authentication, and signing-key settings are omitted here.

```toml
[openshell.gateway]
compute_driver = "v8-example"

[openshell.drivers.v8-example]
socket_path = "<state-dir>/compute.sock"
isolation_backend = "example-v8"

[[openshell.supervisor.isolation_backends]]
name = "example-v8"
endpoint = { kind = "unix", socket_path = "<state-dir>/backend.sock" }
```

The gateway calls the driver on `compute.sock`. The supervisor resolves the
backend name to `backend.sock`.

## Create a sandbox

In another terminal, from this example directory:

```shell
export OPENSHELL_GATEWAY_ENDPOINT=http://127.0.0.1:18770
openshell sandbox create --name v8-demo \
  --keep --no-tty --no-auto-providers -- /work/guest.js
```

The driver starts the supervisor. The backend loads `guest.js` into a fresh V8
isolate with `console.log` and `httpGet`. No filesystem, process, or direct
network API is exposed. `httpGet` sends the request through the Sandbox Protocol;
the supervisor's default policy has no network grants and denies it. No policy
file is needed. The guest succeeds only on that policy denial; transport failures
are errors.

```javascript
const url = "http://1.1.1.1/";
console.log(`Attempting GET ${url} through the supervisor`);
const result = httpGet(url);
if (result !== -1) {
  throw new Error(`Expected a supervisor policy denial, received ${result}`);
}
console.log("Request denied by supervisor network policy (expected)");
```

The create command prints the script's output and returns its exit code. The
sandbox becomes `Completed` on exit code 0 or `Error` on a nonzero exit code.
`--keep` retains the sandbox so you can inspect that result after the command.
`openshell logs v8-demo` shows the supervisor's policy-denial audit.

Add `--detach` to run without attaching; detached creation does not stream guest
output. Use `openshell sandbox connect v8-demo` to attach afterward.

## Inspect and stop

```shell
openshell sandbox list
openshell logs v8-demo
openshell sandbox delete v8-demo
```

Wait for deletion, then press Ctrl-C in the script's terminal to stop all three
processes. Each run uses a fresh state directory and keeps its logs.

This example runs one script at a time, with a 15-second deadline, a 32 MiB
JavaScript heap limit, and 64 KiB per output stream. These limits do not bound
all native V8 resources. It supports synchronous HTTP GET status checks to
numeric addresses through `httpGet`, not the browser `fetch` API. TypeScript,
module imports, DNS, HTTPS, exec, PTY, and recovery are unsupported.
