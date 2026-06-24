# MCP Conformance E2E

This directory contains the OpenShell wrapper for the upstream
`modelcontextprotocol/conformance` runner.

The workflow checks out and builds the upstream conformance repository, then
runs its CLI in client mode. To keep the untrusted upstream node runner off the
host, the wrapper runs it inside a plain Docker container on the e2e Docker
network (not an OpenShell sandbox, which is egress-only and could not accept the
client's inbound connection). The upstream runner starts a real MCP test server
and invokes its client command — `runner-shim.mjs` — with that server URL.

`runner-shim.mjs` stands in for the MCP client: instead of speaking MCP itself,
it posts the server URL back to the host bridge (`host-bridge.py`) over HTTP. The
host bridge runs `client-through-openshell.sh`, which runs the upstream
TypeScript `everything-client` inside an OpenShell client sandbox for each
scenario, so the MCP traffic crosses the sandbox proxy. A single Docker-backed
OpenShell e2e gateway and one reusable client sandbox serve the whole scenario
list. The runner deliberately has no gateway credentials; keeping the privileged
client launch on `host-bridge.py` is the trust boundary. The harness gives the
runner a per-run bridge capability and gives the bridge the runner container IP.
The bridge only accepts requests with that capability, only renders server URLs
whose host is the runner container IP, only forwards the MCP conformance
scenario environment allowlist, and starts the client wrapper with a small host
environment allowlist instead of inheriting token-bearing host environment
variables. It does not use the HTTP peer source address as the runner identity,
because Docker NAT can make legitimate callbacks appear to come from a gateway
address.

The upstream runner reports its test server URL as `localhost`. The runner
container has an ordinary, externally-routable address on the e2e network, so
`runner-shim.mjs` rewrites `localhost` to that container's IP — which the client
sandbox can reach through its egress proxy. The runner container reaches the host
bridge at `host.openshell.internal` (the alias `e2e/with-docker-gateway.sh`
attaches to the CI job container on the e2e network), at `host.docker.internal`
on local Docker Desktop, or via `--add-host ...:host-gateway` on local Linux.

The generated policy uses `protocol: mcp` and allows valid MCP requests to the
conformance server by omitting `method`, which uses the endpoint MCP method
profile. That keeps OpenShell deny-by-default at the network boundary while
allowing the upstream scenarios to exercise MCP behavior. The policy body lives
in `policy-template.yaml`; the wrapper renders its host, port, and path
placeholders from the upstream server URL.

For local runs, build or stage a static supervisor binary and pass it with
`OPENSHELL_DOCKER_SUPERVISOR_BIN` if the default local supervisor build is
linked against a newer glibc than the conformance client image provides.

The pinned upstream checkout includes reference-client fixture drift that is
tracked in `modelcontextprotocol/conformance#345`. The wrapper patches the
checkout before building the client image so the bundled TypeScript client
advertises `elicitation.form.applyDefaults` and accepts the canonical
`elicitation-sep1034-client-defaults` scenario. It also routes `sse-retry` to
the upstream standalone `sse-retry-test.ts` client so the reconnect timing path
is exercised instead of aliasing it to another scenario.

Remove those local workarounds when `OPENSHELL_MCP_CONFORMANCE_REF` points at
an upstream release that includes the `#345` fixes.

When enabling broader upstream suites, add scenarios that OpenShell does not yet
support through the MCP proxy to `expected-failures.yml`. The upstream
runner treats listed failures as allowed and treats stale entries as failures.
The default run uses a static scenario list in `e2e/mcp-conformance.sh`. To
refresh it after changing the pinned upstream ref or default spec, list the
scenarios from the built client image:

```shell
docker run --rm openshell-mcp-conformance-client:local \
  ./node_modules/.bin/tsx src/index.ts list --client --spec-version 2025-11-25
```

Then confirm each scenario has a compatible handler in the pinned
`examples/clients/typescript/everything-client.ts`. The default list skips
opt-in scenarios, including auth/OAuth flows and the slow `sse-retry` scenario.
Set `OPENSHELL_MCP_CONFORMANCE_SCENARIOS=sse-retry` or pass `sse-retry` as an
argument to run it explicitly.

The wrapper caches the pinned upstream checkout, the local conformance runner
build, and the Docker client image. Set
`OPENSHELL_MCP_CONFORMANCE_FORCE_REBUILD=1` to refresh those build artifacts, or
`OPENSHELL_MCP_CONFORMANCE_DOCKER_PULL=1` to pull the client image base during a
rebuild.
