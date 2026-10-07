---
authors:
  - "@drew"
state: review
links:
  - https://github.com/NVIDIA/OpenShell/issues/4266
  - https://github.com/NVIDIA/OpenShell/pull/4267
  - https://github.com/NVIDIA/OpenShell/issues/994
  - https://github.com/NVIDIA/OpenShell/issues/1791
  - https://github.com/NVIDIA/OpenShell/issues/4210
  - https://github.com/NVIDIA/OpenShell/pull/4213
  - https://github.com/NVIDIA/OpenShell/issues/1794
  - https://github.com/NVIDIA/OpenShell/issues/3402
  - https://github.com/NVIDIA/OpenShell/issues/4229
  - https://github.com/NVIDIA/OpenShell/issues/2469
  - https://github.com/NVIDIA/OpenShell/issues/3715
---

# RFC 0017 - Sandbox service exposure

## Summary

For this proposal, the data plane is sandbox service exposure: HTTP and WebSocket traffic to applications running inside sandboxes. Compare three ways to separate it from the control plane while keeping gateway-routed traffic available for simple deployments.

## Motivation

Service exposure needs four things:

1. **Independent scaling.** Prevent application traffic from consuming resources needed for responsive control-plane operations.
2. **Independent access restrictions.** Apply separate network rules to control-plane and application traffic.
3. **Application-owned authentication.** Serve applications without requiring OpenShell request authentication, so applications can authenticate their own clients.
4. **Platform-managed authentication.** Protect applications through the authentication infrastructure used for the control plane, such as Cloudflare tunnels and zero-trust proxies.

## Non-goals

- Move port forwarding or file uploads out of the gateway/control plane.
- Add arbitrary TCP/UDP exposure or scale the sandbox application itself.
- Remove the simple gateway-routed deployment.

## Proposal

### What we have today

```shell
openshell service expose my-sandbox 8080 web
```

OpenShell creates an endpoint and returns a URL shaped like:

```text
https://default--my-sandbox--web.<gateway-base-domain>/
```

SNI selects the server certificate during TLS. HTTP hostname routing selects the application endpoint after the gRPC/HTTP dispatch decision. All of this runs in the gateway process and deployment.

### What is missing

**Independent scaling:** the gateway handles application requests and carries their payloads over supervisor relays. Adding an external frontend alone leaves those payloads in the gateway process.

**Independent access restrictions:** Gateway API can describe separate listeners for `gateway.example.com` (control plane) and `*.gateway.example.com` (applications), but hostname routing alone does not restrict access. An ingress controller can apply separate listener or route policies. Standard Kubernetes NetworkPolicy needs distinct pod or port targets; two hostnames on the same proxy pod and port do not provide that boundary.

**Authentication:** application routes already bypass control-plane RPC authentication and support optional bearer-token passthrough, but inherit the shared listener's TLS requirements. An upstream edge proxy can protect application routes; they do not automatically inherit OpenShell's native OIDC or workspace authorization.

### Option 1: Add a dedicated application proxy

Build a small proxy from the gateway's existing application proxy and relay components, or evaluate Envoy with [reverse tunnels](https://www.envoyproxy.io/docs/envoy/latest/configuration/other_features/reverse_tunnel).

The gateway manages exposure configuration; the dedicated proxy carries application traffic and its supervisor relay connections. Moving both out of the gateway allows independent scaling and network access controls. This adds a deployed component and requires coordination of service configuration and supervisor connections across proxy replicas.

### Option 2: Add separate control-plane and application listeners

This is the approach in [PR #4213](https://github.com/NVIDIA/OpenShell/pull/4213), tracked by [#4210](https://github.com/NVIDIA/OpenShell/issues/4210): add a dedicated application ingress port while retaining the primary gateway listener.

- Application ingress serves HTTP and WebSockets without gateway RPC, authentication, or gateway-tunnel handlers.
- Operators can restrict the ports independently and use different TLS client-authentication requirements.
- Both listeners share the gateway process, deployment resources, and gateway-owned relays.

This addresses access restrictions, but does not provide independent scaling.

### Option 3: Expose supervisor application listeners through Kubernetes Services

Use a Kubernetes Service per supervisor or supervisor shard to expose a dedicated application listener. Multiple sandbox service routes share that backend, including when a supervisor manages multiple tenants. Creating an OpenShell service adds a logical route; it does not require another Kubernetes Service. Per-application Kubernetes Services remain an optional integration choice.

Application ingress routes to the owning supervisor's Service, keeping application bytes out of the gateway. The supervisor resolves the hostname or trusted ingress metadata to a declared service and forwards to its permitted target inside the correct sandbox. The new listener is necessary because a Kubernetes Service cannot directly reach sandbox loopback. It must not expose supervisor management handlers.

A Kubernetes Service selects pods and ports, not HTTP hostnames. Its backends must be able to serve every route sent to it. A single Service across supervisors that own different sandboxes therefore needs additional routing or forwarding. Separate Services targeting the same shared listener do not themselves isolate tenants: the supervisor must validate sandbox identity and effective policy, with authentication, quotas, and accounting scoped to the service or tenant.

This allows separate ingress scaling and access policies while supporting a future multi-tenant supervisor. It is Kubernetes-specific and requires route and backend reconciliation as sandbox ownership changes. Applications still share supervisor resources; this does not scale the applications themselves.

All options retain gateway-owned service declarations and the existing CLI workflow. Keep gateway routing available for low-volume deployments. The choice between the options remains open.

## Implementation plan

1. Select the data path and define configuration, supervisor trust, and service lifecycle behavior.
2. Add the selected mode as opt-in, preserving existing service declarations and URLs where possible; document any DNS, TLS, or endpoint migration.
3. Test HTTP/WebSockets, tenant and authentication boundaries, sandbox ownership changes, deletion and restart behavior, and control-plane responsiveness under application load in the relevant E2E lane. Update deployment docs and related skills before release.

## Risks

- A separate data path adds routing state, certificates, and deployment lifecycle work.
- Stale routes must not expose undeclared targets or route to another sandbox. Backend access must not bypass edge authentication or expose management handlers.
- Application traffic can still exhaust supervisor resources even when the gateway is removed from its path.

## Alternatives

Keeping the current gateway path is simplest, but retains resource coupling. Adding only an external frontend improves edge policy without removing application traffic from the gateway. The three options above compare progressively different deployment boundaries; separate listeners alone do not meet all four requirements.

## Prior art

- [Kubernetes API server proxy](https://kubernetes.io/docs/tasks/access-application-cluster/access-cluster-services/#discovering-builtin-services): a comparison for the current management-server-mediated application path.
- [#994](https://github.com/NVIDIA/OpenShell/issues/994): portable service declarations, supervisor enforcement, and delegated data paths. This RFC focuses on HTTP/WebSocket deployment choices; broader protocol and policy questions remain separate.
- [#1791](https://github.com/NVIDIA/OpenShell/issues/1791): Kubernetes-native exposure, closed as a duplicate of #994 rather than implemented.
- [#1794](https://github.com/NVIDIA/OpenShell/issues/1794) and [#3402](https://github.com/NVIDIA/OpenShell/issues/3402): application bearer-token handling and create-time exposure, whose workflows should remain compatible.
- [#4229](https://github.com/NVIDIA/OpenShell/issues/4229), [#2469](https://github.com/NVIDIA/OpenShell/issues/2469), and [#3715](https://github.com/NVIDIA/OpenShell/issues/3715): related service-readiness and dedicated/shared agentgateway integration work.

## Open questions

- Which path should come first: a dedicated proxy, Kubernetes Services, or both? How does the listener split fit?
- How are service configuration, supervisor connections, and Kubernetes resources reconciled? For shared supervisors, how does ingress find the owning supervisor and follow sandbox ownership changes?
- How should declarations map to effective sandbox policy, and where should per-service authentication be configured?
- What happens to active requests and WebSockets on service deletion, sandbox replacement, or control-plane failure?
