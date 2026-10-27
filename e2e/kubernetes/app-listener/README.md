# Supervisor application listener verification

Use a Kubernetes development cluster with the current gateway and supervisor
images. This fixture exercises the listener without discovery or the reference
proxy. The opt-in Helm values are
`deploy/helm/openshell/ci/values-app-listener.yaml`.

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

Inspect supervisor Pods. Dedicated supervisors optionally expose
`os-app-<sandbox-id>`; inspect that Service's EndpointSlices. Shared supervisors
have no app Service: select the Pod IP actually owning the sandbox and use its
configured app port. Do not select an arbitrary member when more than one is
present. Check ownership through supervisor admission/release logs in this
stage; automated owner selection belongs to the later discovery API.

From a permitted client Pod, mount only the public app certificate/CA and run:

```shell
curl --cacert /test/app-ca.crt \
  --connect-to default--demo--web.services.example.com:443:SUPERVISOR_POD_IP:9443 \
  https://default--demo--web.services.example.com/
```

For a dedicated supervisor, repeat using its headless Service DNS name instead
of the Pod IP. Verify both paths through ordinary cluster networking. A
port-forward alone does not verify Service selection or NetworkPolicy.

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
TLS mount, or app Service. Retain the dedicated driver `create_service` option
while disabling and recreating a sandbox to verify cleanup of its previously
owned endpoint. Confirm gateway ingress still works in each mode.

Dedicated endpoint reconciliation runs more than once during creation. Verify
that it accepts its own non-controller Sandbox owner reference and has Service
`patch`/`delete` permissions when `create_service` is configured. Foreign-owned
Services must be left untouched, and cleanup uses UID/resource-version
preconditions.

For HA pool validation after integration with #4864, use at least two supervisor
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
