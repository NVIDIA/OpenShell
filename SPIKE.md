# Node Enforcer Topology Findings

Date: 2026-05-29

## Summary

This branch explored how OpenShell can remove `privileged: true` from sandbox
workload pods while preserving the current network proxy value proposition and
keeping the supervisor responsible for agent lifecycle.

The core finding is that Linux still needs an elevated component to modify
network enforcement for an already-running sandbox. The viable short-term shape
is to move that authority out of the agent-controlled sandbox container and into
an operator-controlled node component.

That does not eliminate privilege from the system. It moves privilege to a
smaller, auditable infrastructure component.

## Problem

The existing Kubernetes sandbox topology needs Linux permissions that are
problematic for managed clusters and hardened runtimes:

- Sandbox containers needed elevated network permissions to install bypass
  prevention rules.
- GKE with gVisor rejected privileged sandbox pods with:
  `Privileged=true is not supported`.
- A per-sandbox `--privileged` CLI flag was the wrong product shape because this
  is gateway/operator configuration, not per-sandbox user configuration.
- RuntimeClass-based isolation is useful, but depending on gVisor or Kata would
  make OpenShell rely on cluster-specific runtime availability.
- Kubernetes `NetworkPolicy` and most CNI-level controls are too static for our
  current need: OpenShell must be able to update enforcement for a running
  sandbox as policy changes.

## Prototype Topology

The implemented prototype splits the supervisor into runtime roles:

- `combined`: current local-style behavior where one supervisor owns lifecycle
  and hard controls.
- `workload`: runs inside the sandbox pod and owns policy loading, proxying,
  SSH, logs, and agent lifecycle.
- `enforcer`: runs as a privileged node-side component.

The Kubernetes topology uses:

- A workload supervisor inside each sandbox pod.
- A privileged `node-enforcer` DaemonSet, one pod per node.
- A node-local registration flow from workload supervisor to node enforcer.
- Host-side nftables installation into the sandbox pod network namespace.

The workload supervisor still owns the agent lifecycle. The node enforcer does
not run agent code, does not need provider credentials, and does not need access
to sandbox files.

## Enforcement Model

The node enforcer currently installs a coarse nftables table in the sandbox
pod's network namespace:

- Allow loopback so sandbox processes can reach the local OpenShell proxy.
- Allow established and related connections.
- Allow UID 0 traffic so the supervisor-owned proxy can reach upstreams.
- Reject non-root TCP and UDP egress so sandbox-user traffic must go through the
  proxy, where OPA and L7 policy are enforced.

This restores the observable behavior required by the existing bypass-detection
e2e test: direct raw sockets from sandbox user code fail fast with
`ECONNREFUSED` instead of hanging.

## Control Flow

The current prototype enforcement flow is registration-driven:

1. The gateway creates sandbox pods with `supervisor_role = "workload"` and
   `network_enforcement_mode = "external-enforcer"`.

2. The Kubernetes driver injects node-local routing data into each sandbox pod:
   `OPENSHELL_NODE_IP` from `status.hostIP`, `OPENSHELL_POD_IP` from
   `status.podIP`, and `OPENSHELL_ENFORCER_ENDPOINT`. If no custom endpoint is
   configured, the endpoint defaults to `http://$(OPENSHELL_NODE_IP):17671`.

3. The node enforcer DaemonSet runs the same supervisor binary with
   `supervisor_role = "enforcer"`. In that role it does not start an agent
   supervisor; it binds `0.0.0.0:17671` and waits for workload registrations.

4. The workload supervisor starts normally, loads policy, computes the effective
   network enforcement mode, and registers with the node enforcer before
   spawning the agent process. The registration is an HTTP `POST` to
   `/v1/sandboxes/{sandbox_id}/register` with:

   ```json
   {
     "sandbox_id": "sb-...",
     "sandbox_name": "optional-name",
     "pod_ip": "10.x.y.z",
     "protocol": "openshell-node-enforcer-prototype-v1"
   }
   ```

5. The node enforcer accepts the registration, chooses the target pod IP from
   the payload, and falls back to the peer address only when the peer is
   non-loopback. Loopback registrations without a pod IP are accepted but do not
   install host-side enforcement.

6. On Linux, the enforcer finds the target pod network namespace by scanning
   `/proc/<pid>/net/fib_trie` for IPv4 or `/proc/<pid>/net/if_inet6` for IPv6.
   For IPv4 it requires the pod IP to appear as `/32 host LOCAL`, which avoids
   selecting the host namespace where the pod IP may exist only as a routed
   `UNICAST` entry.

7. The enforcer opens `/proc/<pid>/ns/net`, forks `nft` from a trusted absolute
   path, calls `setns(CLONE_NEWNET)` in the child process, deletes any prior
   OpenShell table, and loads the generated `openshell_external_enforcer`
   ruleset into the pod namespace.

8. Once the table is installed, non-root TCP and UDP egress from the sandbox
   namespace is rejected, loopback remains available, established flows remain
   available, and UID 0 traffic remains available for the supervisor-owned
   proxy. User code must therefore reach the network through the OpenShell proxy
   path where policy is enforced.

The workload supervisor remains in charge of policy loading, proxying, SSH,
settings reloads, logs, and agent lifecycle. The node enforcer owns only
host-side namespace lookup and coarse kernel egress enforcement.

Current limitations:

- Reconciliation is registration-triggered, not yet watch-based.
- Re-registration is idempotent because the enforcer deletes and recreates its
  owned nftables table.
- Cleanup for deleted pods, restarted pods, and stale namespace state remains a
  hardening item.
- Registration currently uses prototype HTTP and must be replaced or wrapped
  with strong workload identity before production use.

## Multiple Gateway Behavior

The topology can support multiple gateways scheduling sandboxes into the same
cluster because enforcement is node-local and pod-local, not gateway-local:

- Each sandbox pod resolves its own `OPENSHELL_NODE_IP` and `OPENSHELL_POD_IP`
  from Kubernetes downward API fields.
- Each workload supervisor registers with the node enforcer on the node where
  its sandbox pod was scheduled.
- The node enforcer installs nftables state into the registered pod's network
  namespace. The table name can be the same across sandboxes because each pod
  has its own network namespace.
- `sandbox_id` is currently used for logs and nft log prefixes; isolation comes
  from the selected pod network namespace, not from a gateway-specific table.

The important deployment constraint is that the node enforcer should be treated
as shared node infrastructure. A node can only have one process binding the
default host-network listener `0.0.0.0:17671`. If multiple gateway releases each
enable their own node-enforcer DaemonSet on the same nodes with the same listen
address, they will compete for the same port and duplicate the privileged
component.

For a shared cluster, the expected shape is one node-enforcer DaemonSet per
node pool or cluster security boundary, with all participating gateways pointing
their sandbox workloads at that node-local endpoint. If separate gateway
installations need isolated enforcers, they must use separate node pools, node
selectors, or distinct listener ports and matching `OPENSHELL_ENFORCER_ENDPOINT`
templates.

This also raises the bar for the hardening work. Multi-gateway support needs
registration authorization that understands allowed gateway identities,
namespaces, and sandbox pod labels. The enforcer must verify that a registered
pod IP belongs to an OpenShell-owned sandbox pod on the same node and that the
registering workload is allowed to ask for enforcement on that pod.

## Validation

Validated against the development Kubernetes cluster using the normal OpenShell
gateway path. GKE was used as a real managed-cluster validation target, but it
should not be part of the implementation criteria.

The unchanged Kubernetes e2e test passed:

```shell
OPENSHELL_GATEWAY_ENDPOINT=http://34.171.165.42 \
  cargo test --manifest-path e2e/rust/Cargo.toml \
  --features e2e-kubernetes \
  --test bypass_detection \
  -- --nocapture
```

Result:

```text
test bypass_attempt_is_rejected_fast ... ok
1 passed; 0 failed
```

The full existing Rust e2e suite also passed unchanged against the Kubernetes
gateway once the local e2e invocation used a named temporary gateway config:

```shell
XDG_CONFIG_HOME=/private/tmp/openshell-gke/e2e-config \
OPENSHELL_GATEWAY=gke-e2e \
OPENSHELL_E2E_DRIVER=kubernetes \
  cargo test --manifest-path e2e/rust/Cargo.toml \
  --features e2e \
  --no-fail-fast \
  -- --nocapture
```

Result:

```text
all e2e test targets passed
```

Important test harness note: the e2e settings test expects the local CLI to be
built with `openshell-core/dev-settings`, which the normal e2e scripts already
do. Direct ad hoc cargo invocations should rebuild `openshell-cli` with that
feature before running the full suite.

Node-enforcer logs showed the expected action:

```text
Observed sandbox workload registration
Reconciling sandbox network enforcement
Installing sandbox network egress enforcement for pod 10.40.1.35
Sandbox network egress enforcement installed for pod 10.40.1.35 in /proc/309096/ns/net
```

## Key Debug Finding

The first version looked up a pod network namespace by scanning
`/proc/*/net/fib_trie` for the pod IP. That was insufficient because the host
network namespace also contains pod IPs as routed `UNICAST` entries.

The enforcer installed rules into the host namespace instead of the sandbox pod
namespace, so bypass attempts timed out rather than being rejected.

The fix was to require that the pod IP is present as a local address in the
target namespace:

```text
10.40.1.33
/32 host LOCAL
```

That distinction selected the sandbox pod namespace instead of the host
namespace and made the unchanged e2e test pass.

## Envoy Gateway Timeout Finding

The managed-cluster validation exposed a second, unrelated deployment issue:
Envoy Gateway was terminating long-lived gRPC streams after about 15 seconds.
The symptom was:

```text
h2 protocol error: error reading a body from connection
```

This affected the existing `WatchSandbox`, `ForwardTcp`, and supervisor
`RelayStream` paths used by `sandbox create -- <cmd>`, upload/create, sync, and
TTY lifecycle tests. The sandbox pods themselves were running and the node
enforcer had installed rules correctly; the failure was at the external gateway
proxy layer.

The fix belongs to the deployment that installs Envoy Gateway, not to the
OpenShell product Helm chart. Envoy Gateway deployments can attach a
`BackendTrafficPolicy` to the OpenShell `GRPCRoute`:

```yaml
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: BackendTrafficPolicy
metadata:
  name: openshell-grpc-streams
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: GRPCRoute
      name: openshell
  timeout:
    http:
      requestTimeout: 0s
      maxStreamDuration: 0s
```

After that policy was applied, Envoy reported it as accepted and the previous
15-second failures passed without test changes.

## Product Finding

This topology shifts the privileged boundary from the sandbox workload to a
node-level infrastructure component.

That is likely the right direction if the goal is:

- Agent-controlled workload containers are not privileged.
- RuntimeClass is optional, not required.
- OpenShell keeps dynamic network proxy enforcement.
- The supervisor remains responsible for the agent lifecycle.
- Non-Kubernetes deployments can keep the existing combined supervisor mode.
- External ingress and Gateway API controllers are deployment concerns. If they
  impose request or stream duration limits, the deployment must configure them
  to preserve OpenShell's long-lived gRPC streams.

It is not a claim that the system has no privileged code. On Linux, dynamic
network namespace enforcement needs some trusted component with elevated
authority unless we delegate entirely to a CNI, runtime, or kernel feature.

## Why Not Only RuntimeClass

gVisor or Kata can still be valuable defense-in-depth, especially for kernel
isolation, but making them required creates deployment friction:

- Not all clusters have the runtime installed.
- RuntimeClass behavior differs by provider.
- Some runtime classes reject the Linux privileges needed by the old topology.
- RuntimeClass does not solve dynamic per-sandbox policy updates by itself.

The better product shape is to support runtime classes as an optional outer
isolation layer, not as the core mechanism required for OpenShell network
enforcement.

## Why Not Only CNI or NetworkPolicy

Kubernetes `NetworkPolicy` is too coarse and too asynchronous for our immediate
needs:

- It is not naturally tied to OpenShell's per-sandbox policy lifecycle.
- It is awkward for fast policy changes on running sandboxes.
- It does not preserve OpenShell's L7 proxy semantics by itself.
- CNI-specific extensions would create provider and plugin dependencies.

A future CNI or eBPF backend could be worthwhile, but it should be another
backend behind the enforcement interface, not the only implementation.

## Current Risks

The prototype proves the topology, but it is not yet ready as a hardened
production component.

Known risks:

- Registration is prototype-level HTTP and is not yet strongly authenticated.
- The enforcer trusts pod IP registration too much.
- The node enforcer is privileged and host-networked/host-PID, so compromise has
  node-level blast radius.
- Cleanup and reconciliation need to handle deleted pods, restarted pods, and
  stale nftables state.
- Multi-gateway deployments need a shared-enforcer model or explicit
  per-enforcer scheduling and port separation. The current Helm shape can deploy
  one enforcer DaemonSet per release, which is not safe to enable repeatedly on
  the same nodes without coordination.
- The current rules are coarse: UID 0 is allowed, non-root TCP/UDP is rejected.
- IPv6 namespace lookup exists conceptually but has not been validated in the
  managed-cluster path.
- Observability is useful but should become structured enough for operators to
  prove what pod/netns/rules were acted on.
- Edge proxies can break otherwise healthy sandboxes if they impose short
  request or stream duration timeouts on gRPC. This is deployment-specific and
  should be validated wherever OpenShell is exposed through a proxy.

## Hardening Plan

Before this becomes more than a prototype, the node enforcer should be hardened
around identity, scope, and reconciliation.

Recommended next steps:

1. Authenticate registration.
   Use Kubernetes-projected workload identity, mTLS, or a gateway-minted token
   so the node enforcer can verify the registering sandbox.

2. Authorize against Kubernetes state.
   Verify that the registered pod IP belongs to an OpenShell-owned sandbox pod
   scheduled on the same node as the enforcer. In multi-gateway clusters, this
   authorization also needs to validate the gateway identity, namespace, and
   tenant boundary allowed to register that sandbox.

3. Reduce privilege where possible.
   Determine whether `privileged: true` can be replaced with a narrower set of
   Linux capabilities and namespace access. If host PID is still needed, document
   why.

4. Add reconciliation.
   Watch OpenShell sandbox pods, ensure expected rules exist, and remove stale
   rules when pods are deleted.

5. Make rule ownership explicit.
   Keep all nftables state in an OpenShell-owned table and make installs
   idempotent.

6. Strengthen logs and metrics.
   Emit clear events for registration, authorization, selected netns, ruleset
   install, cleanup, and failures.

7. Keep e2e parity non-negotiable.
   The existing e2e tests should remain unaltered and passing. Topology changes
   should be invisible at the behavioral API layer.

## Implementation Notes From This Branch

The branch added configuration and code paths for:

- `OPENSHELL_SUPERVISOR_ROLE`
- `OPENSHELL_NETWORK_ENFORCEMENT_MODE`
- `OPENSHELL_ENFORCER_ENDPOINT`
- `OPENSHELL_NODE_IP`
- `OPENSHELL_POD_IP`
- Helm `nodeEnforcer` configuration
- Helm `server.supervisorRole`
- Helm `server.networkEnforcementMode`
- Helm `server.sandboxImagePullPolicy`
- Kubernetes driver injection of node and pod IP environment variables
- Supervisor image packaging with `nftables`
- Deployment-owned Envoy Gateway `BackendTrafficPolicy` for long-lived
  OpenShell gRPC streams.

The development cluster currently uses:

- `server.supervisorRole: workload`
- `server.networkEnforcementMode: external-enforcer`
- `server.sandboxImagePullPolicy: IfNotPresent`
- `nodeEnforcer.enabled: true`
- An Envoy Gateway `BackendTrafficPolicy` with `requestTimeout = 0s` and
  `maxStreamDuration = 0s`.

## Recommendation

Continue with the node-enforcer topology as the next prototype target. It gives
us the cleanest path to unprivileged sandbox workload pods without giving up the
OpenShell proxy model or requiring a specific runtime class.

Do not present it as removing privilege entirely. Present it as moving privileged
network enforcement into a narrow, operator-controlled component that can be
authenticated, audited, reconciled, and hardened independently from untrusted
agent workloads.

Keep Envoy Gateway and other ingress-controller tuning out of the product chart
unless OpenShell intentionally takes ownership of that controller. The product
requirement is that long-lived gRPC streams must be supported; the deployment
implementation should provide the controller-specific policy.
