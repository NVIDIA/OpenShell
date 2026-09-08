# Topology matrix

This non-normative matrix compares representative mappings of RFC 0012's logical
roles. It records role placement, sharing, and relationship to the workload
kernel; it does not select a deployment or establish conformance.

## Representative placements

| Pattern | Control and network-mediation placement | Boundary-mode placement | Workload-kernel relationship | Topology status |
|---|---|---|---|---|
| **Co-located/in-pod** | With the workload; the legacy in-process backend may omit boundary mode | Same process when used | Trusted components share the workload's host kernel | Placement implemented (original topology) |
| **Kubernetes proxy pod** | Trusted control pod | Boundary-mode workload entrypoint owning the workload PID and network namespaces | Shared cluster-node kernel; pod security boundaries separate control from workload | Implemented in #3144; requires a conforming NetworkPolicy CNI and trusted namespace |
| **Docker** | Gateway host | Trusted container entrypoint sharing the workload container's PID and network namespaces | Shared host kernel | Implemented in #2965 |
| **MicroVM** | Gateway host | Guest PID 1 | Boundary mode shares the guest kernel; control is kernel-separated | Implemented in #2945 |

The Kubernetes proxy-pod topology uses the same boundary protocol as Docker and
VM, with per-boundary TLS because the connection traverses the pod network.
Kubernetes-specific code provisions the workload fence, pair labels, boundary
Service, control Deployment, immutable bootstrap Secret, and stable
namespace/Sandbox/Deployment/NetworkPolicy claims. The workload pod has no
direct egress; attributed proxy streams cross the TLS channel and hostname
resolution occurs on the control side. Admission requires an explicitly acknowledged conforming CNI and a
namespace in which untrusted principals cannot create pods, mutate pair labels,
or read bootstrap Secrets. Pod readiness or the existence of a `NetworkPolicy`
object alone does not prove enforcement.

## Durable rules

- Every active boundary has one verified descriptor, one trusted
  `SandboxContext`, one control role, and at most one boundary role. Those
  processes form one logical supervisor.
- Physical processes and listeners may be shared, but lifecycle state, policy,
  binary identity, enforcement, and cleanup remain isolated per boundary.
- Moving a privileged component does not itself provide kernel separation.

## Kernel relationships

| Relationship | Meaning |
|---|---|
| **Shared host kernel** | The workload and the trusted components relied on for containment run on the host's kernel. |
| **Shared guest or application kernel** | The workload and those trusted components share one isolated kernel: a VM guest kernel or a userspace application kernel. |
| **Kernel-separated** | The trusted components relied on for containment run outside the workload's kernel. |

## Status

This matrix is non-normative. It illustrates implementations of RFC 0012; it
does not extend the contract.
