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

The generated policy uses `protocol: mcp`, inserts the conformance runner's spec revision into the endpoint allowlist, and sets `mcp.allow_all_known_mcp_methods: true` so omitted rule methods use the selected MCP method profile. The renderer accepts OpenShell's supported revisions, `2025-03-26`, `2025-06-18`, `2025-11-25`, and `2026-07-28`. The policy body lives in `policy-template.yaml`; the wrapper renders its MCP revision, host, port, and path placeholders from the upstream server URL.

OpenShell checks each request against the policy revision and delegates JSON-RPC structure and MCP method, direction, message-kind, parameter, and metadata type checks to `tower-mcp-types`, pinned to `0.22.2`. These checks follow Tower's deserialization and inspection APIs and do not establish complete JSON-schema conformance. OpenShell owns revision allowlisting, HTTP/body consistency, request limits, and policy enforcement. For the 2025 revisions, a valid standalone `initialize` proposes a version; later requests select their revision through `MCP-Protocol-Version`, with `2025-03-26` as the missing-header fallback. The sessionless `2026-07-28` profile carries one JSON-RPC request or explicitly allowed extension notification per POST. Requests require per-request metadata and matching protocol-version, method, and applicable name headers. Extension notifications require an exact method allow rule and the version header, but no request metadata or method/name mirrors. Responses and SSE payloads are relayed without policy parsing. The conformance runner and its reference client exercise behavior beyond these request inspection checks.

`OPENSHELL_MCP_CONFORMANCE_SPEC_VERSION` defaults to `2025-11-25`. The default scenarios in `e2e/mcp-conformance.sh` are `initialize`, `tools_call`, and `elicitation-sep1034-client-defaults`, selected for the pinned upstream fixture and this default revision. A passing default run does not establish `2026-07-28` conformance coverage. To exercise that revision through this harness, select an upstream fixture and scenario handlers that implement its sessionless request contract, then set the spec version and scenario list together.

For local runs, the wrapper builds `openshell/supervisor:dev` automatically
when no supervisor image override is set. Set `OPENSHELL_DOCKER_SUPERVISOR_IMAGE`
or `OPENSHELL_SUPERVISOR_IMAGE` to use a prebuilt pullable image instead.

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

Then confirm each scenario has a compatible handler in the pinned `examples/clients/typescript/everything-client.ts`. The default list skips opt-in scenarios, including auth/OAuth flows and the slow `sse-retry` scenario. Set `OPENSHELL_MCP_CONFORMANCE_SCENARIOS` to `sse-retry` or pass `sse-retry` as an argument to run it explicitly.

The wrapper caches the pinned upstream checkout, the local conformance runner build, and the Docker client image. Set `OPENSHELL_MCP_CONFORMANCE_FORCE_REBUILD` to `1` to refresh those build artifacts, or `OPENSHELL_MCP_CONFORMANCE_DOCKER_PULL` to `1` to pull the client image base during a rebuild.
