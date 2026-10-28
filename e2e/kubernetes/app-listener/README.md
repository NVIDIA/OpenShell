# Supervisor application listener verification

Use a Kubernetes development cluster with the current gateway and supervisor
images. This fixture exercises the listener without discovery or the reference
proxy. The opt-in Helm values are
`deploy/helm/openshell/ci/values-app-listener.yaml`.

## Repeatable local checks

The local and CI entry point creates an isolated Helm release, temporary TLS
Secret and client resources, runs the checks, and removes the release/namespace:

```shell
KUBECONFIG="$PWD/kubeconfig" \
IMAGE_TAG=dev OPENSHELL_REGISTRY=openshell \
OPENSHELL_E2E_APP_TOPOLOGY=shared \
OPENSHELL_E2E_APP_TAKEOVER=abrupt \
  mise run e2e:kubernetes:app-listener
```

Build and import matching `openshell/gateway:dev`, `openshell/supervisor:dev`,
and `openshell/sandbox:dev` images first, or set the registry/tag to images
already loaded into the cluster. Build the CLI or set `OPENSHELL_BIN` to it.
Set `OPENSHELL_E2E_KUBE_CONTEXT` to select a context explicitly. The cluster must
enforce NetworkPolicy; the local k3s default does. The task installs the pinned
Agent Sandbox controller only when its CRD is absent.
Set `OPENSHELL_E2E_KUBECONFIG` when testing a separate cluster whose kubeconfig
differs from the repository's mise environment.

`OPENSHELL_E2E_APP_TOPOLOGY` accepts `dedicated` (default) or `shared`;
`OPENSHELL_E2E_APP_DELIVERY` accepts `push` (default) or `poll`;
`OPENSHELL_E2E_APP_TAKEOVER` accepts `graceful` (default) or `abrupt` for shared
supervisors. Dedicated runs include gateway-outage expiry. Every run also
disables the listener and verifies absent app sockets/TLS mounts/Services and
continued gateway application ingress. Logs, events, and resource summaries
are written under `results/app-listener/`, without TLS private keys or Secrets.

GitHub Actions runs four matrix cases under the existing `test:e2e` label:
dedicated push/poll and shared graceful/abrupt takeover. These jobs use the
reusable Kubernetes workflow, with kindnet replaced by pinned Calico for policy
enforcement, and participate in `Core E2E result`. CI uploads the evidence even
on failure. They still require the normal current-head `/ok to test <SHA>`
approval mirror.

### Checking an already deployed release

Build the gateway, supervisor, sandbox, and CLI from the branch under test and
deploy them through the local Helm development workflow. Use an isolated release
namespace with gateway TLS, unauthenticated development API access, and the app
listener enabled. Provide the application TLS Secret before installing the
release. The workload and client fixture use `python:3.12-slim`.

Run from the repository root, supplying the public application certificate/CA:

```shell
KUBECONFIG="$PWD/kubeconfig" uv run --no-project python \
  e2e/kubernetes/app-listener/verify.py \
  --namespace listener-review-shared \
  --gateway-endpoint https://localhost:29203 \
  --forward-gateway service/listener-review \
  --app-ca /path/to/app-ca.crt \
  --network-policy \
  --takeover graceful
```

Use the actual namespace and gateway Service name of the test release. The
runner maintains its API port-forward across gateway restarts; application
traffic originates in client Pods and uses cluster networking. Application TLS
verifies the supplied CA and hostname. The development API connection uses
`--gateway-insecure` with an isolated temporary CLI configuration.

The runner creates and cleans up its sandboxes, client Pods, public-CA ConfigMap,
and ingress policies. It checks named/unnamed HTTP routes, public Host/Origin and
cookies, credential stripping and explicit bearer passthrough, unknown routes,
Host/SNI mismatch, quiet WebSockets beyond 30 seconds, selective withdrawal, and
re-exposure without restarting the application. Both topologies use supervisor
Pod IPs and verify that no per-sandbox app Services are created.

`--network-policy` requires an enforcing cluster network implementation, such as
the local k3s default. A default kind cluster needs a policy-enforcing CNI before
this assertion can establish isolation.

For a two-member shared pool, `--takeover graceful` deletes the owning Pod and
checks that its sandbox keeps its Pod UID, runtime generation, process, and
in-memory state, while another owner's WebSocket survives. `--takeover abrupt`
first SIGKILLs the supervisor container through the local k3d/kind node's Docker
container, preventing a graceful leave; it requires access to that Docker engine.
These options deliberately interrupt test resources in the supplied namespace.

For dedicated topology, omit `--takeover`. Add
`--expire-gateway statefulset/listener-review` (using the actual workload name)
to scale the isolated gateway to zero, verify route/stream expiry, restore its
original replica count, and check application survival. Repeat with gateway
`config_delivery_mode` set to `push` and `poll`.

The lower-level runner leaves the Helm release and TLS Secret in place. Use
`--disabled --gateway-service <service>` instead of takeover/expiry flags to
check an already disabled release. Configuration rejection and the additional
deployment cleanup scenarios remain in the manual checklist below.

## Manual deployment and additional scenarios

Before deployment, provide an operator-owned `openshell-app-tls` Secret in the
supervisor namespace with `tls.crt` and `tls.key` for
`*.services.example.com`. Keep private keys outside the checkout. Allow a labeled
test-client Pod to reach supervisor TCP port 9443 through a separate
NetworkPolicy. The normal runtime/control port rules do not grant app access.
Deploy through the repository's Helm development workflow with these values.

Create two sandboxes running an HTTP/WebSocket test application bound to loopback
port 8080. Expose named and unnamed services using the existing CLI, including
`openshell service expose <sandbox> 8080 web`. CLI URLs still use gateway mode in
this stage. Use these direct-listener hostnames instead:

- `default--<sandbox>.services.example.com` for the unnamed service.
- `default--<sandbox>--web.services.example.com` for the named service.

Inspect supervisor Pods. Both dedicated and shared supervisors expose the
listener directly on their Pod IPs without app Services. Select the Pod IP
actually owning the sandbox and use its configured app port. Do not select an
arbitrary member when more than one is present. Check ownership through
supervisor admission/release logs in this stage; automated owner selection
belongs to the later discovery API.

From a permitted client Pod, mount only the public app certificate/CA and run:

```shell
curl --cacert /test/app-ca.crt \
  --connect-to default--demo--web.services.example.com:443:SUPERVISOR_POD_IP:9443 \
  https://default--demo--web.services.example.com/
```

Verify this path through ordinary cluster networking. A port-forward alone does
not verify NetworkPolicy.

Verify HTTP and WebSockets, public Host/Origin, application session cookies,
unknown SNI, mismatched Host, undeclared services, bearer stripping/passthrough,
and lack of access to another sandbox's ports. Change or remove one service
while its WebSocket is open: its connection closes while an unrelated service's
connection survives. Recreate the sandbox and confirm old streams cannot revive.

Exercise configuration polling and push modes. In push mode, leave configuration
unchanged for longer than 30 seconds and confirm ingress remains usable while
the session is healthy. Reject configuration and confirm ingress closes. Stop
configuration/session refresh and require routes and streams to expire after
the remaining freshness lease once session loss is detected.

Run with listener configuration omitted, explicitly disabled despite complete
TLS/port options, and explicitly enabled. Disabled deployments have no app port,
TLS mount, or app Service. Confirm gateway ingress still works in each mode.

For HA pool validation, use at least two supervisor
members with distinct sandbox owners. Move one owner through graceful downscale
and abrupt loss. Existing streams may disconnect; after selecting the new owner,
new HTTP/WebSocket connections must work without restarting the workload.
Validate unchanged workload generation/process memory, rejection of old-owner
connectors, and continued service for the unaffected sandbox. A static ingress
must be updated manually in this stage; automated owner tracking belongs to
subsequent discovery work.

The local Rust listener tests use a real TLS client and backend RPC connector.
They supplement this live cluster check; they do not establish HA pool recovery
or real Kubernetes reachability.
